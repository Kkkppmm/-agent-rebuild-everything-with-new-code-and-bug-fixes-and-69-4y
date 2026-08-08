"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

MAKEFILE_NAMES = ("Makefile", "makefile", "GNUmakefile")
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
DANGEROUS_RM_PATTERN = re.compile(
    r"\brm\s+.*(-[a-zA-Z]*f[a-zA-Z]*\s+)?(/(?:\s|$)|/\*|~(?:/|\s|$)|\$\(HOME\)|\$\{HOME\})",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
EVAL_EXEC_PATTERN = re.compile(r"\b(eval|exec)\s+", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:?]?=\s*['\"]?[^\s'\"]{4,}",
    re.IGNORECASE,
)
CHMOD_777_PATTERN = re.compile(r"\bchmod\s+777\b", re.IGNORECASE)
FORCE_PUSH_PATTERN = re.compile(
    r"\bgit\s+push\b[^\n]*(--force|-f)\b",
    re.IGNORECASE,
)
DD_DEVICE_PATTERN = re.compile(r"\bdd\b[^\n]*/dev/[a-z]", re.IGNORECASE)
UNPINNED_PIP_PATTERN = re.compile(
    r"\bpip3?\s+install\b(?![^\n]*[=<>!~])[^\n]*\b[a-zA-Z0-9][a-zA-Z0-9._-]*\s*$",
    re.IGNORECASE,
)
WILDCARD_DELETE_PATTERN = re.compile(r"\brm\s+[^\n]*\s-\w*f\w*\s+\*\s*$", re.IGNORECASE)
TAB_CONTINUATION = re.compile(r"^\t")


@dataclass
class MakefileFinding:
    """A security or best-practice issue in a Makefile."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MakefileTarget:
    """Parsed metadata about a Makefile target."""

    name: str
    lineno: int
    is_phony: bool = False
    recipe_lines: int = 0


@dataclass
class MakefileInfo:
    """Parsed metadata about a Makefile."""

    path: str
    targets: list[MakefileTarget] = field(default_factory=list)
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
    return path.name in MAKEFILE_NAMES or path.suffix == ".mk"


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for curl-pipe-to-shell, dangerous ``rm -rf``, sudo usage, eval/exec,
  secrets in variables, chmod 777, force pushes, and unpinned pip installs.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        max_depth: int = 6,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.max_depth = max_depth
        self._findings: list[MakefileFinding] | None = None
        self._stats: MakefileStats | None = None
        self._infos: list[MakefileInfo] | None = None

    def makefiles(self) -> list[Path]:
        """Return Makefile paths found in the project."""
        found: list[Path] = []
        for name in MAKEFILE_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)

        root_depth = len(self.root.parts)
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(self.root).parts
            if len(rel_parts) > self.max_depth:
                continue
            if any(part in self.ignore_dirs for part in rel_parts):
                continue
            if _is_makefile(path) and path not in found:
                found.append(path)
        return found

    def _add_finding(
        self,
        findings: list[MakefileFinding],
        *,
        kind: str,
        severity: str,
        message: str,
        path: Path,
        lineno: int,
        line: str,
    ) -> None:
        findings.append(
            MakefileFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path),
                lineno=lineno,
                line=line.strip(),
            )
        )

    def _parse_targets(self, lines: list[str]) -> tuple[list[MakefileTarget], bool]:
        targets: list[MakefileTarget] = []
        phony_targets: set[str] = set()
        has_phony = False

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(".PHONY:"):
                has_phony = True
                names = stripped.split(":", 1)[1].strip().split()
                phony_targets.update(names)
            elif stripped.startswith(".PHONY "):
                has_phony = True
                names = stripped.split(None, 1)[1].strip().split()
                phony_targets.update(names)

        for i, line in enumerate(lines, start=1):
            if line.startswith("\t") or line.startswith(" "):
                continue
            if ":" not in line or line.strip().startswith("#"):
                continue
            if line.strip().startswith("."):
                continue
            target_part = line.split(":", 1)[0].strip()
            if not target_part or "%" in target_part:
                continue
            name = target_part.split()[0]
            recipe_lines = 0
            for j in range(i, min(i + 20, len(lines))):
                if j < len(lines) and TAB_CONTINUATION.match(lines[j]):
                    recipe_lines += 1
            targets.append(
                MakefileTarget(
                    name=name,
                    lineno=i,
                    is_phony=name in phony_targets,
                    recipe_lines=recipe_lines,
                )
            )

        for target in targets:
            target.is_phony = target.name in phony_targets
        return targets, has_phony

    def _analyze_file(self, path: Path) -> tuple[list[MakefileFinding], MakefileInfo]:
        findings: list[MakefileFinding] = []
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        targets, has_phony = self._parse_targets(lines)

        for lineno, line in enumerate(lines, start=1):
            if line.strip().startswith("#"):
                continue

            if CURL_PIPE_SHELL_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell — use checksum-verified downloads",
                    path=path,
                    lineno=lineno,
                    line=line,
                )

            if DANGEROUS_RM_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="dangerous_rm",
                    severity="high",
                    message="Dangerous rm command — may delete system or home directories",
                    path=path,
                    lineno=lineno,
                    line=line,
                )
            elif WILDCARD_DELETE_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="wildcard_delete",
                    severity="medium",
                    message="Wildcard rm — prefer explicit file lists to avoid accidental deletion",
                    path=path,
                    lineno=lineno,
                    line=line,
                )

            if SUDO_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="sudo_usage",
                    severity="medium",
                    message="sudo in Makefile recipe — avoid requiring elevated privileges in builds",
                    path=path,
                    lineno=lineno,
                    line=line,
                )

            if EVAL_EXEC_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="eval_exec",
                    severity="high",
                    message="eval/exec in recipe — avoid dynamic code execution in build scripts",
                    path=path,
                    lineno=lineno,
                    line=line,
                )

            if SECRET_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="secret_in_makefile",
                    severity="high",
                    message="Possible secret in Makefile — use environment variables instead",
                    path=path,
                    lineno=lineno,
                    line=line,
                )

            if CHMOD_777_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="chmod_777",
                    severity="medium",
                    message="chmod 777 — use restrictive permissions (e.g. 755 or 644)",
                    path=path,
                    lineno=lineno,
                    line=line,
                )

            if FORCE_PUSH_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="force_push",
                    severity="high",
                    message="git push --force — force pushes can overwrite shared history",
                    path=path,
                    lineno=lineno,
                    line=line,
                )

            if DD_DEVICE_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="dd_to_device",
                    severity="high",
                    message="dd writing to block device — extremely destructive if misconfigured",
                    path=path,
                    lineno=lineno,
                    line=line,
                )

            if UNPINNED_PIP_PATTERN.search(line) and not line.strip().startswith("#"):
                self._add_finding(
                    findings,
                    kind="unpinned_pip",
                    severity="low",
                    message="Unpinned pip install — pin versions for reproducible builds",
                    path=path,
                    lineno=lineno,
                    line=line,
                )

        common_targets = {"clean", "install", "test", "build", "deploy"}
        for target in targets:
            if target.name in common_targets and not target.is_phony and not has_phony:
                self._add_finding(
                    findings,
                    kind="missing_phony",
                    severity="low",
                    message=f"Target '{target.name}' should be declared .PHONY to avoid file conflicts",
                    path=path,
                    lineno=target.lineno,
                    line=f"{target.name}:",
                )

        info = MakefileInfo(
            path=str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path),
            targets=targets,
            has_phony=has_phony,
            lines=len(lines),
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
.PHONY: help install test lint clean build

PYTHON ?= python3
VENV ?= .venv

help:  ## Show available targets
\t@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\\n", $$1, $$2}'

install:  ## Install dependencies into a virtual environment
\t$(PYTHON) -m venv $(VENV)
\t$(VENV)/bin/pip install --upgrade pip
\t$(VENV)/bin/pip install -e ".[dev]"

test:  ## Run the test suite
\t$(VENV)/bin/python -m pytest

lint:  ## Run linters
\t$(VENV)/bin/ruff check .

clean:  ## Remove build artifacts
\trm -rf build dist *.egg-info .pytest_cache .ruff_cache
\tfind . -type d -name __pycache__ -exec rm -rf {} +

build:  ## Build distribution packages
\t$(VENV)/bin/python -m build
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
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            target_names = ", ".join(t.name for t in info.targets[:8]) or "none"
            lines.append(f"  - {info.path}: {len(info.targets)} target(s) [{target_names}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
