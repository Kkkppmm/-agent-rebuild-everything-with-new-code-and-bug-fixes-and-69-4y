"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAKEFILE_NAMES = ("Makefile", "GNUmakefile", "makefile", "Makefile.in", "Makefile.am")
MAKEFILE_SUFFIXES = (".mk",)

SECRET_VAR_PATTERN = re.compile(
    r"^(?:export\s+)?(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:?]?=\s*[^\s$]{4,}",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
DANGEROUS_RM_PATTERN = re.compile(
    r"\brm\s+(-[^\s]*\s+)*(-[^\s]*\s+)*(/\s*$|/\s+\*|/\*\s*$|/\.\s|/\.\.\s|-[^\s]*r[^\s]*\s+/\s*$|-[^\s]*r[^\s]*\s+/\*)",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"\bchmod\s+777\b|\bchmod\s+a\+rwx\b", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"\beval\b", re.IGNORECASE)
INSECURE_TLS_PATTERN = re.compile(
    r"curl\s+[^\n]*\s-k\b|wget\s+[^\n]*--no-check-certificate",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(r"docker\s+run\b[^\n]*--privileged\b", re.IGNORECASE)
SHELL_CURL_PATTERN = re.compile(
    r"\$\(\s*shell\s*,?\s*(curl|wget)\b",
    re.IGNORECASE,
)
DANGEROUS_DISK_PATTERN = re.compile(r"\b(mkfs|fdisk|dd\s+if=/dev/)\b", re.IGNORECASE)
UNPINNED_GIT_CLONE_PATTERN = re.compile(
    r"git\s+clone\b[^\n]*\b(main|master|HEAD)\b",
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
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MakefileTargetInfo:
    """Parsed metadata about a Makefile target."""

    name: str
    has_recipe: bool = False
    uses_sudo: bool = False
    uses_shell: bool = False


@dataclass
class MakefileInfo:
    """Parsed metadata about a Makefile."""

    path: str
    targets: list[MakefileTargetInfo] = field(default_factory=list)
    has_phony: bool = False
    has_oneshell: bool = False
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
    lower = name.lower()
    if lower.endswith(MAKEFILE_SUFFIXES):
        return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].rstrip()
    return line.rstrip()


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for destructive ``rm`` commands, curl-pipe-to-shell patterns,
    hardcoded secrets, sudo usage, overly permissive chmod, eval, and
  other common Makefile misconfigurations.
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
        current_target: MakefileTargetInfo | None = None
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

            stripped = line.lstrip()
            if stripped.startswith(".PHONY:") or stripped.startswith(".PHONY "):
                info.has_phony = True
            if stripped.startswith(".ONESHELL:") or stripped == ".ONESHELL":
                info.has_oneshell = True

            if line and not line.startswith("\t") and not line.startswith(" ") and ":" in line:
                target_name = line.split(":", 1)[0].strip()
                if target_name and not target_name.startswith("."):
                    current_target = MakefileTargetInfo(name=target_name)
                    info.targets.append(current_target)
                    if line.split(":", 1)[1].strip():
                        current_target.has_recipe = True

            is_recipe = line.startswith("\t") or (line.startswith(" ") and current_target is not None)
            recipe_body = line.lstrip() if is_recipe else line

            if is_recipe and current_target is not None:
                current_target.has_recipe = True
                if SUDO_PATTERN.search(recipe_body):
                    current_target.uses_sudo = True
                if "$(shell" in recipe_body or "$(" in recipe_body:
                    current_target.uses_shell = True

            check_line = recipe_body if is_recipe else line

            if SECRET_VAR_PATTERN.match(check_line):
                findings.append(
                    MakefileFinding(
                        kind="secret_in_var",
                        severity="high",
                        message="potential secret in Makefile variable — use environment or secret store",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(check_line):
                findings.append(
                    MakefileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DANGEROUS_RM_PATTERN.search(check_line):
                findings.append(
                    MakefileFinding(
                        kind="dangerous_rm",
                        severity="high",
                        message="destructive rm command — risk of deleting system or project files",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SUDO_PATTERN.search(check_line):
                findings.append(
                    MakefileFinding(
                        kind="sudo_usage",
                        severity="medium",
                        message="sudo in Makefile recipe — prefer containerized or user-scoped commands",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CHMOD_777_PATTERN.search(check_line):
                findings.append(
                    MakefileFinding(
                        kind="chmod_777",
                        severity="medium",
                        message="overly permissive chmod — use least-privilege file permissions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EVAL_PATTERN.search(check_line):
                findings.append(
                    MakefileFinding(
                        kind="eval_usage",
                        severity="high",
                        message="eval in Makefile is unsafe — avoid dynamic command execution",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_TLS_PATTERN.search(check_line):
                findings.append(
                    MakefileFinding(
                        kind="insecure_tls",
                        severity="medium",
                        message="disabling TLS verification in curl/wget is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(check_line):
                findings.append(
                    MakefileFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="docker run --privileged grants excessive container permissions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SHELL_CURL_PATTERN.search(check_line):
                findings.append(
                    MakefileFinding(
                        kind="shell_download",
                        severity="medium",
                        message="$(shell curl/wget ...) downloads at parse time — pin and verify artifacts",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DANGEROUS_DISK_PATTERN.search(check_line):
                findings.append(
                    MakefileFinding(
                        kind="dangerous_disk_op",
                        severity="high",
                        message="disk formatting or raw device operations are dangerous in build scripts",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_GIT_CLONE_PATTERN.search(check_line):
                findings.append(
                    MakefileFinding(
                        kind="unpinned_git_clone",
                        severity="low",
                        message="git clone without pinned tag/commit — pin dependencies for reproducible builds",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        common_targets = {t.name for t in info.targets}
        expected_phony = {"clean", "install", "test", "build", "all", "help", "lint", "format"}
        if common_targets & expected_phony and not info.has_phony:
            findings.append(
                MakefileFinding(
                    kind="missing_phony",
                    severity="low",
                    message="common targets without .PHONY — files can shadow target names",
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
        total_targets = 0

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)
            total_targets += len(info.targets)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
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
.PHONY: help install test lint format clean build

help:
\t@echo "Targets: install test lint format clean build"

install:
\tpip install -e ".[dev]"

test:
\tpython -m pytest

lint:
\truff check .

format:
\truff format .

build:
\tpython -m build

clean:
\trm -rf build dist .pytest_cache .ruff_cache
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
            lines.append(
                f"  - {info.path}: {len(info.targets)} target(s), "
                f".PHONY={'yes' if info.has_phony else 'no'}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
