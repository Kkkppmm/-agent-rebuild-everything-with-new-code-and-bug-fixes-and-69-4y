"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAKEFILE_NAMES = ("Makefile", "makefile", "GNUmakefile")
MAKEFILE_SUFFIXES = (".mk",)

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\b", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"\bchmod\s+777\b", re.IGNORECASE)
RM_RF_ROOT_PATTERN = re.compile(r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*\s+/\b|\brm\s+-rf\s+/\s")
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
DOCKER_PRIVILEGED_PATTERN = re.compile(r"docker\s+run\b[^;\n]*--privileged\b", re.IGNORECASE)
FORCE_PUSH_PATTERN = re.compile(r"\bgit\s+push\b[^;\n]*--force\b", re.IGNORECASE)
UNQUOTED_VAR_PATTERN = re.compile(r"\$\([^)]+\)|\$\{[^}]+\}")
DANGEROUS_TARGET_PATTERN = re.compile(
    r"^(clean|distclean|destroy|nuke|wipe)\s*:",
    re.IGNORECASE,
)


@dataclass
class MakefileFinding:
    """A security or best-practice issue in a Makefile."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    target: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        tgt = f" ({self.target})" if self.target else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{tgt} — {self.message}"


@dataclass
class MakefileInfo:
    """Parsed metadata about a Makefile."""

    path: str
    targets: list[str] = field(default_factory=list)
    has_phony: bool = False
    has_help: bool = False
    lines: int = 0


@dataclass
class MakefileStats:
    """Aggregate Makefile analysis statistics."""

    makefiles: int
    findings: int
    targets: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_makefile(path: Path) -> bool:
    name = path.name
    lower = name.lower()
    if lower in ("makefile", "gnumakefile"):
        return True
    if name == "Makefile":
        return True
    if lower.endswith(".mk"):
        return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].rstrip()
    return line.rstrip()


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for curl-pipe-to-shell, eval, sudo, chmod 777, rm -rf /,
    hardcoded secrets, docker --privileged, force-push, and other
    common misconfigurations in build automation.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MakefileFinding] | None = None
        self._stats: MakefileStats | None = None
        self._infos: list[MakefileInfo] | None = None

    def makefiles(self) -> list[Path]:
        """Return Makefile paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_makefile(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[MakefileFinding], MakefileInfo]:
        findings: list[MakefileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MakefileInfo(path=rel)

        info = MakefileInfo(path=rel, lines=len(raw_lines))
        current_target = ""
        continuation = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            if line.endswith("\\"):
                continuation = (continuation + " " + line[:-1]).strip()
                continue

            if continuation:
                line = (continuation + " " + line).strip()
                continuation = ""

            if line.startswith(".PHONY"):
                info.has_phony = True

            if re.match(r"^help\s*:", line, re.IGNORECASE):
                info.has_help = True

            if ":" in line and not line.startswith("\t") and not line.startswith(" "):
                target_part = line.split(":", 1)[0].strip()
                if target_part and not target_part.startswith("."):
                    for tgt in target_part.split():
                        if tgt and tgt not in info.targets:
                            info.targets.append(tgt)
                            current_target = tgt
                            if DANGEROUS_TARGET_PATTERN.match(line):
                                findings.append(
                                    MakefileFinding(
                                        kind="dangerous_target",
                                        severity="low",
                                        message=(
                                            f"target '{tgt}' may run destructive commands — "
                                            "add safeguards or document clearly"
                                        ),
                                        path=rel,
                                        lineno=lineno,
                                        target=tgt,
                                        line=raw.strip(),
                                    )
                                )

            recipe = line.lstrip("\t")
            if not recipe or recipe == line:
                continue

            checks = [
                (
                    CURL_PIPE_SHELL_PATTERN,
                    "curl_pipe_shell",
                    "high",
                    "curl/wget piped to shell — download and verify scripts explicitly",
                ),
                (
                    EVAL_PATTERN,
                    "eval_usage",
                    "high",
                    "eval in recipe — avoid dynamic shell execution",
                ),
                (
                    RM_RF_ROOT_PATTERN,
                    "rm_rf_root",
                    "high",
                    "rm -rf / detected — catastrophic if executed",
                ),
                (
                    SECRET_PATTERN,
                    "secret_in_makefile",
                    "high",
                    "possible hardcoded secret in Makefile — use environment variables",
                ),
                (
                    DOCKER_PRIVILEGED_PATTERN,
                    "docker_privileged",
                    "high",
                    "docker run --privileged — avoid privileged containers",
                ),
                (
                    SUDO_PATTERN,
                    "sudo_usage",
                    "medium",
                    "sudo in recipe — prefer containerized or user-scoped commands",
                ),
                (
                    CHMOD_777_PATTERN,
                    "chmod_777",
                    "medium",
                    "chmod 777 — use restrictive file permissions",
                ),
                (
                    FORCE_PUSH_PATTERN,
                    "force_push",
                    "medium",
                    "git push --force — risky in automated targets",
                ),
            ]

            for pattern, kind, severity, message in checks:
                if pattern.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind=kind,
                            severity=severity,
                            message=message,
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )

            if UNQUOTED_VAR_PATTERN.search(recipe) and "shell" in recipe.lower():
                findings.append(
                    MakefileFinding(
                        kind="unquoted_shell_var",
                        severity="low",
                        message="unquoted variable in shell recipe — quote expansions to prevent word splitting",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=raw.strip(),
                    )
                )

        if info.targets and not info.has_phony:
            findings.append(
                MakefileFinding(
                    kind="missing_phony",
                    severity="low",
                    message="no .PHONY declarations — file targets may conflict with real files",
                    path=rel,
                    lineno=0,
                )
            )

        return findings, info

    def analyze(self) -> list[MakefileFinding]:
        """Scan Makefiles and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MakefileFinding] = []
        infos: list[MakefileInfo] = []
        paths = self.makefiles()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        total_targets = sum(len(i.targets) for i in infos)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = MakefileStats(
            makefiles=len(paths),
            findings=len(findings),
            targets=total_targets,
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MakefileStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MakefileInfo]:
        """Return parsed Makefile metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no Makefiles)."""
        self.analyze()
        stats = self.stats
        if stats.makefiles == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Makefile template."""
        return """\
# Generated by DevAI MakefileAnalyzer
.PHONY: help install test lint clean

help:
\t@echo "Targets: install test lint clean"

install:
\tpip install -e ".[dev]"

test:
\tpython -m pytest

lint:
\truff check src tests

clean:
\tfind . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
\trm -rf .pytest_cache .ruff_cache dist build *.egg-info
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.makefiles == 0:
            return "Makefiles: none found"
        return (
            f"Makefiles: {stats.makefiles} file(s), {stats.targets} target(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Makefile analysis:",
            f"  makefiles: {stats.makefiles}",
            f"  targets: {stats.targets}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            target_list = ", ".join(info.targets[:8]) or "none"
            lines.append(f"  - {info.path}: [{target_list}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
