"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAKEFILE_NAMES = ("Makefile", "GNUmakefile", "makefile")
MAKEFILE_SUFFIXES = (".mk", ".make")

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
DANGEROUS_RM_PATTERN = re.compile(
    r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?(/|\*|~|\$\(HOME\)|\$\{HOME\})",
    re.IGNORECASE,
)
CHMOD_777_PATTERN = re.compile(r"\bchmod\s+777\b", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\s+", re.IGNORECASE)
EVAL_EXEC_PATTERN = re.compile(r"(?<![-\w/])(eval|exec)\s+", re.IGNORECASE)
SECRET_ASSIGN_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|\btoken\b|credential|private[_-]?key)\s*[:=]\s*['\"]?[^\s'\"#]{4,}",
    re.IGNORECASE,
)
DOCKER_RUN_ROOT_PATTERN = re.compile(
    r"docker\s+run\b(?![^\n]*--user)",
    re.IGNORECASE,
)
UNQUOTED_SHELL_VAR_PATTERN = re.compile(r"\$\([^)]+\)|`[^`]+`")


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
    lower = name.lower()
    if name in MAKEFILE_NAMES or lower in MAKEFILE_NAMES:
        return True
    if lower.endswith(MAKEFILE_SUFFIXES):
        return True
    return False


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for curl-pipe-to-shell, dangerous ``rm`` commands, ``chmod 777``,
    ``sudo`` usage, ``eval``/``exec``, secrets in variable assignments, and
  unhardened ``docker run`` invocations.
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

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith(".PHONY:") or line.startswith(".PHONY "):
                info.has_phony = True
                continue

            if ":" in line and not line.startswith("\t") and not line.startswith(" ") and "=" not in line:
                target_part = line.split("#", 1)[0].strip()
                if target_part.endswith(":"):
                    current_target = target_part[:-1].split(":")[0].strip()
                    if current_target and current_target not in info.targets:
                        info.targets.append(current_target)

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — supply-chain risk",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if DANGEROUS_RM_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="dangerous_rm",
                        severity="high",
                        message="rm targets root, home, or wildcard paths",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if CHMOD_777_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="chmod_777",
                        severity="medium",
                        message="chmod 777 grants world-writable permissions",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if SUDO_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="sudo_usage",
                        severity="medium",
                        message="sudo in Makefile recipe — prefer least privilege",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if EVAL_EXEC_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="eval_exec",
                        severity="high",
                        message="eval/exec in shell recipe — injection risk",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if SECRET_ASSIGN_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="secret_in_makefile",
                        severity="high",
                        message="possible secret hardcoded in Makefile variable",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if DOCKER_RUN_ROOT_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="docker_run_no_user",
                        severity="medium",
                        message="docker run without --user may run as root",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if UNQUOTED_SHELL_VAR_PATTERN.search(line) and "echo" not in line.lower():
                findings.append(
                    MakefileFinding(
                        kind="command_substitution",
                        severity="low",
                        message="command substitution in recipe — verify inputs are trusted",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
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
\tfind . -type d -name __pycache__ -exec rm -rf {} +
\tfind . -type f -name '*.pyc' -delete
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        stats = self.stats
        if stats.makefiles == 0:
            return "Makefiles: none found"
        return (
            f"Makefiles: {stats.makefiles} file(s), "
            f"{stats.targets} target(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low) — health {self.health_score():.0f}/100"
        )

    def to_context(self) -> str:
        """Export findings as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Makefile analysis:",
            f"  makefiles: {stats.makefiles}",
            f"  targets: {stats.targets}",
            f"  findings: {stats.findings}",
            f"  health_score: {self.health_score():.0f}/100",
            "",
        ]
        for finding in self._findings or []:
            lines.append(finding.format())
        return "\n".join(lines)
