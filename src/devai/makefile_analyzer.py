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
DANGEROUS_RM_PATTERN = re.compile(
    r"\brm\s+.*(-rf?|--recursive).*(/\s|/\*|/usr|/etc|/var|/home|\$\(HOME\)|\$\{HOME\})",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"\bchmod\s+777\b", re.IGNORECASE)
EVAL_EXEC_PATTERN = re.compile(r"\b(eval|exec)\s+", re.IGNORECASE)
SECRET_ASSIGN_PATTERN = re.compile(
    r"^(?:export\s+)?(PASSWORD|SECRET|API[_-]?KEY|TOKEN|CREDENTIAL|PRIVATE[_-]?KEY)\s*[:?]?=\s*[^\s$]",
    re.IGNORECASE,
)
UNPINNED_PIP_PATTERN = re.compile(
    r"\bpip3?\s+install\s+(?!.*(?:==|>=|<=|~=|--require-hashes))([a-zA-Z0-9][a-zA-Z0-9._-]*)",
    re.IGNORECASE,
)
CURL_INSECURE_PATTERN = re.compile(r"\bcurl\b.*\s(-k|--insecure)\b", re.IGNORECASE)
FORCE_PUSH_PATTERN = re.compile(r"\bgit\s+push\b.*\s(-f|--force)\b", re.IGNORECASE)
DOCKER_RUN_PRIVILEGED_PATTERN = re.compile(r"\bdocker\s+run\b.*\s--privileged\b", re.IGNORECASE)


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
    lines: int = 0


@dataclass
class MakefileStats:
    """Aggregate Makefile analysis statistics."""

    makefiles: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_makefile(path: Path) -> bool:
    name = path.name
    lower = name.lower()
    if name in MAKEFILE_NAMES:
        return True
    if lower.endswith(MAKEFILE_SUFFIXES):
        return True
    return False


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for curl-pipe-to-shell, dangerous ``rm -rf``, hardcoded secrets,
    sudo usage, chmod 777, eval/exec, unpinned pip installs, and other
    common Makefile anti-patterns.
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
            if not path.is_file():
                continue
            if _is_makefile(path):
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
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.endswith("\\"):
                continuation += line[:-1] + " "
                continue

            if continuation:
                line = (continuation + line).strip()
                continuation = ""

            if line.startswith(".PHONY:"):
                info.has_phony = True
                for target in line.split(":", 1)[1].split():
                    if target and target not in info.targets:
                        info.targets.append(target)
                continue

            if re.match(r"^[a-zA-Z0-9_.-]+:", line) and not line.startswith("."):
                current_target = line.split(":", 1)[0].strip()
                if current_target and current_target not in info.targets:
                    info.targets.append(current_target)
                recipe = line.split(":", 1)[1].strip()
                if recipe:
                    line = recipe
                else:
                    continue

            self._check_line(findings, rel, lineno, line, current_target)

        return findings, info

    def _check_line(
        self,
        findings: list[MakefileFinding],
        rel: str,
        lineno: int,
        line: str,
        target: str,
    ) -> None:
        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high", "recipe pipes curl/wget to shell — supply-chain risk"),
            (DANGEROUS_RM_PATTERN, "dangerous_rm", "high", "recipe uses rm -rf on a broad path — data-loss risk"),
            (SECRET_ASSIGN_PATTERN, "secret_in_makefile", "high", "potential secret hardcoded in Makefile — use env vars"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "recipe uses eval/exec — arbitrary code execution risk"),
            (DOCKER_RUN_PRIVILEGED_PATTERN, "docker_privileged", "high", "docker run --privileged weakens container isolation"),
            (FORCE_PUSH_PATTERN, "git_force_push", "medium", "recipe force-pushes to git — can overwrite remote history"),
            (SUDO_PATTERN, "sudo_usage", "medium", "recipe uses sudo — prefer non-root targets or documented privilege"),
            (CHMOD_777_PATTERN, "chmod_777", "medium", "recipe sets world-writable permissions (chmod 777)"),
            (CURL_INSECURE_PATTERN, "curl_insecure", "medium", "recipe uses curl with -k/--insecure — TLS verification disabled"),
            (UNPINNED_PIP_PATTERN, "unpinned_pip", "low", "pip install without version pin — builds may be non-reproducible"),
        ]
        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    MakefileFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        target=target,
                        line=line[:120],
                    )
                )

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

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = MakefileStats(
            makefiles=len(paths),
            findings=len(findings),
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
.PHONY: help install lint test clean

help:
\t@echo "Targets: install lint test clean"

install:
\tpip install -e ".[dev]"

lint:
\truff check src tests

test:
\tpytest

clean:
\tfind . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
\tfind . -type f -name '*.pyc' -delete 2>/dev/null || true
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.makefiles == 0:
            return "Makefile: no Makefiles found"
        return (
            f"Makefile: {stats.makefiles} file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Makefile analysis:",
            f"  makefiles: {stats.makefiles}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            targets = ", ".join(info.targets[:8]) or "none"
            lines.append(f"  - {info.path}: {len(info.targets)} target(s) [{targets}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
