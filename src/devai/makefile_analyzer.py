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
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
RM_RF_ROOT_PATTERN = re.compile(r"rm\s+-rf\s+/(?:\s|$)", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"chmod\s+777\b", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*[:=]\s*['\"]?[^\s'\"#]+",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\$\(eval\b", re.IGNORECASE)
SHELL_TRUE_PATTERN = re.compile(r"SHELL\s*=\s*/bin/(?:ba)?sh", re.IGNORECASE)
FORCE_RM_PATTERN = re.compile(r"rm\s+-rf\s+\$\(", re.IGNORECASE)
CURL_INSECURE_PATTERN = re.compile(r"curl\s+[^\n]*\s-k\b", re.IGNORECASE)
UNQUOTED_VAR_PATTERN = re.compile(r"\$\([^)]*\$\([^)]*\)[^)]*\)")


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
    uses_shell: bool = False
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
    if name in MAKEFILE_NAMES:
        return True
    if name.endswith(".mk"):
        return True
    if name.lower().startswith("makefile.") and path.suffix:
        return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].rstrip()
    return line.rstrip()


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for curl-pipe-to-shell, sudo usage, destructive rm -rf /,
    hardcoded secrets, chmod 777, and unsafe shell patterns.
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
            line = _strip_comment(raw)
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith(".PHONY:"):
                info.has_phony = True

            if re.match(r"^[a-zA-Z0-9_.-]+:", stripped) and not stripped.startswith("."):
                current_target = stripped.split(":", 1)[0].strip()
                info.targets.append(current_target)

            if SHELL_TRUE_PATTERN.search(line):
                info.uses_shell = True

            checks = [
                (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high", "piping curl/wget to shell is unsafe"),
                (SUDO_PATTERN, "sudo_usage", "medium", "sudo in Makefile recipes can escalate privileges unexpectedly"),
                (RM_RF_ROOT_PATTERN, "rm_rf_root", "high", "rm -rf / is catastrophically destructive"),
                (CHMOD_777_PATTERN, "chmod_777", "high", "chmod 777 grants world-writable permissions"),
                (SECRET_PATTERN, "hardcoded_secret", "high", "potential hardcoded secret in Makefile"),
                (EVAL_PATTERN, "eval_usage", "medium", "$(eval ...) can execute arbitrary Makefile code"),
                (FORCE_RM_PATTERN, "rm_rf_variable", "medium", "rm -rf with unvalidated variable can delete wrong paths"),
                (CURL_INSECURE_PATTERN, "curl_insecure", "medium", "curl -k disables TLS certificate verification"),
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
                            target=current_target,
                            line=raw.strip(),
                        )
                    )

        if info.targets and not info.has_phony:
            findings.append(
                MakefileFinding(
                    kind="missing_phony",
                    severity="low",
                    message="no .PHONY declarations — phony targets may conflict with files",
                    path=rel,
                    lineno=1,
                    line="",
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

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
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
        """Scaffold a safe Makefile template."""
        return """\
# Generated by DevAI MakefileAnalyzer
.PHONY: help install test lint clean

PYTHON ?= python3
VENV ?= .venv

help:
\t@echo "Targets: install test lint clean"

install:
\t$(PYTHON) -m venv $(VENV)
\t$(VENV)/bin/pip install -e ".[dev]"

test:
\t$(VENV)/bin/pytest

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
            return "Makefiles: none found"
        return (
            f"Makefiles: {stats.makefiles} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        lines = [
            "Makefile analysis:",
            self.summary(),
            f"Health score: {self.health_score()}/100",
        ]
        if self._findings:
            lines.append("")
            lines.append("Findings:")
            for finding in self._findings[:50]:
                lines.append(f"  - {finding.format()}")
            if len(self._findings) > 50:
                lines.append(f"  ... and {len(self._findings) - 50} more")
        return "\n".join(lines)
