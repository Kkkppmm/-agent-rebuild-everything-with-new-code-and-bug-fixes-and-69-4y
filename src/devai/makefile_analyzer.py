"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAKEFILE_NAMES = (
    "Makefile",
    "makefile",
    "GNUmakefile",
    "gnumakefile",
)

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
DANGEROUS_RM_PATTERN = re.compile(
    r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?(/|\$\{?HOME\}?|\$\(HOME\)|\*|\$\*)",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"\beval\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"\bchmod\s+777\b", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
SECRET_EXPORT_PATTERN = re.compile(
    r"export\s+(PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIAL|AWS_SECRET)[A-Z0-9_]*\s*=",
    re.IGNORECASE,
)
UNQUOTED_SHELL_VAR_PATTERN = re.compile(
    r"(?:^|[;&|]\s*)(?:rm|cp|mv|curl|wget|sh|bash)\s+[^'\"]*\$\{?[A-Za-z_][A-Za-z0-9_]*\}?",
    re.IGNORECASE,
)
DOCKER_RUN_PRIVILEGED_PATTERN = re.compile(
    r"docker\s+run\b[^\\]*--privileged\b",
    re.IGNORECASE,
)
DOCKER_SOCK_MOUNT_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
FORCE_PUSH_PATTERN = re.compile(r"\bgit\s+push\b[^\\]*--force\b", re.IGNORECASE)
CURL_INSECURE_PATTERN = re.compile(r"curl\b[^\\]*\s-k\b", re.IGNORECASE)


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
    targets: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_makefile(path: Path) -> bool:
    name = path.name
    if name in MAKEFILE_NAMES:
        return True
    if name.endswith(".mk") or name.endswith(".make"):
        return True
    return False


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for dangerous ``rm -rf`` patterns, curl-pipe-to-shell, ``sudo`` usage,
    hardcoded secrets, unquoted shell variables, privileged Docker runs, and
    other common Makefile anti-patterns.
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

    def _add_finding(
        self,
        findings: list[MakefileFinding],
        *,
        kind: str,
        severity: str,
        message: str,
        path: str,
        lineno: int,
        target: str = "",
        line: str = "",
    ) -> None:
        findings.append(
            MakefileFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=path,
                lineno=lineno,
                target=target,
                line=line.strip(),
            )
        )

    def _analyze_file(self, path: Path) -> tuple[list[MakefileFinding], MakefileInfo]:
        findings: list[MakefileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MakefileInfo(path=rel)

        info = MakefileInfo(path=rel, lines=len(raw_lines))
        current_target = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith(".PHONY"):
                info.has_phony = True

            is_recipe = raw.startswith("\t") or (raw.startswith(" ") and not raw.startswith("  "))

            if not is_recipe and ":" in line:
                target_part = line.split(":", 1)[0].strip()
                if (
                    target_part
                    and not target_part.startswith(".")
                    and "://" not in line
                    and "/" not in target_part
                ):
                    current_target = target_part.split()[0]
                    if current_target not in info.targets:
                        info.targets.append(current_target)
                continue

            if not is_recipe:
                continue

            recipe = raw.lstrip("\t ").strip()
            if not recipe:
                continue

            if CURL_PIPE_SHELL_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell — use checksum-verified downloads",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
                )

            if DANGEROUS_RM_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="dangerous_rm",
                    severity="high",
                    message="dangerous rm pattern — avoid rm -rf on /, $HOME, or wildcards",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
                )

            if SUDO_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="sudo_usage",
                    severity="medium",
                    message="sudo in Makefile recipe — prefer containerized or user-scoped commands",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
                )

            if EVAL_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="eval_usage",
                    severity="high",
                    message="eval in recipe — avoid dynamic shell execution",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
                )

            if CHMOD_777_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="chmod_777",
                    severity="medium",
                    message="chmod 777 — use restrictive permissions",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
                )

            if SECRET_PATTERN.search(recipe) or SECRET_EXPORT_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="secret_in_makefile",
                    severity="high",
                    message="hardcoded secret in Makefile — use environment variables or a secrets manager",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
                )

            if UNQUOTED_SHELL_VAR_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="unquoted_shell_var",
                    severity="low",
                    message="unquoted shell variable in command — quote variables to prevent word splitting",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
                )

            if DOCKER_RUN_PRIVILEGED_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="docker_privileged",
                    severity="high",
                    message="docker run --privileged — avoid privileged containers",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
                )

            if DOCKER_SOCK_MOUNT_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="docker_sock_mount",
                    severity="high",
                    message="Docker socket mount grants host-level access",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
                )

            if FORCE_PUSH_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="git_force_push",
                    severity="medium",
                    message="git push --force in Makefile — risky in shared branches",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
                )

            if CURL_INSECURE_PATTERN.search(recipe):
                self._add_finding(
                    findings,
                    kind="curl_insecure",
                    severity="medium",
                    message="curl -k disables TLS verification",
                    path=rel,
                    lineno=lineno,
                    target=current_target,
                    line=recipe,
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

PYTHON ?= python3
VENV ?= .venv

help:
\t@echo "Targets: install test lint clean"

install:
\t$(PYTHON) -m venv $(VENV)
\t$(VENV)/bin/pip install --upgrade pip
\t$(VENV)/bin/pip install -e ".[dev]"

test:
\t$(VENV)/bin/python -m pytest

lint:
\t$(VENV)/bin/ruff check src tests

clean:
\trm -rf build dist *.egg-info .pytest_cache .ruff_cache
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.makefiles == 0:
            return "Makefile: no Makefiles found"
        return (
            f"Makefile: {stats.makefiles} file(s), {stats.targets} target(s), "
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
            f"  health score: {self.health_score():.0f}/100",
        ]
        if self._findings:
            lines.append("")
            lines.append("Findings:")
            for finding in self._findings[:20]:
                lines.append(f"  - {finding.format()}")
            if len(self._findings) > 20:
                lines.append(f"  ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
