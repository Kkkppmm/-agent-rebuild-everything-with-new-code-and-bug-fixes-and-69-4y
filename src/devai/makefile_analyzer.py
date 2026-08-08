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
    r"\brm\s+(-[^\s]*f[^\s]*\s+)?(-[^\s]*r[^\s]*\s+)?(/|\$\(HOME\)|\$\{HOME\}|~)(?:\s|$)",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"\beval\b", re.IGNORECASE)
CHMOD_WORLD_WRITABLE_PATTERN = re.compile(r"\bchmod\s+777\b", re.IGNORECASE)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*"
    r"(?:['\"][^'\"]{4,}|sk_[a-zA-Z0-9_]{8,})",
    re.IGNORECASE,
)
DOCKER_PRIVILEGED_PATTERN = re.compile(r"docker\s+run\b[^\\]*--privileged\b", re.IGNORECASE)
FORCE_FLAG_PATTERN = re.compile(r"\bmake\s+-B\b|\b--always-make\b", re.IGNORECASE)
RECURSIVE_MAKE_PATTERN = re.compile(r"\$\(MAKE\)\s+-C\b|\bmake\s+-C\b", re.IGNORECASE)
TARGET_PATTERN = re.compile(r"^([a-zA-Z0-9_.-]+)\s*:")


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
    is_phony: bool = False
    has_recipe: bool = False


@dataclass
class MakefileInfo:
    """Parsed metadata about a Makefile."""

    path: str
    targets: list[MakefileTargetInfo] = field(default_factory=list)
    has_phony_decl: bool = False
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
    return name.endswith(MAKEFILE_SUFFIXES)


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for dangerous ``rm`` patterns, curl-pipe-to-shell, ``sudo`` usage,
    secrets in variable assignments, world-writable ``chmod``, privileged Docker
    runs, and missing ``.PHONY`` declarations for common targets.
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
        phony_targets: set[str] = set()
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

            if line.startswith(".PHONY:"):
                info.has_phony_decl = True
                names = line.split(":", 1)[1].strip().split()
                phony_targets.update(names)
                for name in names:
                    for target in info.targets:
                        if target.name == name:
                            target.is_phony = True
                continue

            if line.startswith(".PHONY "):
                info.has_phony_decl = True
                names = line.split(None, 1)[1].strip().split() if " " in line else []
                phony_targets.update(names)
                for name in names:
                    for target in info.targets:
                        if target.name == name:
                            target.is_phony = True
                continue

            target_match = TARGET_PATTERN.match(line)
            if target_match and not line.startswith("\t") and not line.startswith(" "):
                target_name = target_match.group(1)
                current_target = MakefileTargetInfo(
                    name=target_name,
                    is_phony=target_name in phony_targets,
                )
                info.targets.append(current_target)
                continue

            if line.startswith("\t") or (current_target and line and not line.startswith(".")):
                if current_target:
                    current_target.has_recipe = True

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — avoid remote code execution in recipes",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DANGEROUS_RM_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="dangerous_rm",
                        severity="high",
                        message="dangerous rm targeting root or home — risk of destructive deletion",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SUDO_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="sudo_usage",
                        severity="medium",
                        message="sudo in recipe — prefer non-privileged build steps",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EVAL_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="eval_usage",
                        severity="high",
                        message="eval in recipe — risk of arbitrary command execution",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CHMOD_WORLD_WRITABLE_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="chmod_777",
                        severity="medium",
                        message="chmod 777 grants world-writable permissions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SECRET_ASSIGNMENT_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="secret_in_makefile",
                        severity="high",
                        message="possible secret hardcoded in Makefile variable",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_PRIVILEGED_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="docker_privileged",
                        severity="high",
                        message="docker run with --privileged — avoid elevated container privileges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FORCE_FLAG_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="force_rebuild",
                        severity="low",
                        message="make -B forces rebuild of all targets — may hide stale dependency issues",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if RECURSIVE_MAKE_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="recursive_make",
                        severity="low",
                        message="recursive make invocation — consider consolidating build graph",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        common_targets = {"clean", "install", "test", "build", "all", "check", "lint", "format"}
        for target in info.targets:
            if target.name in common_targets and not target.is_phony and target.has_recipe:
                findings.append(
                    MakefileFinding(
                        kind="missing_phony",
                        severity="low",
                        message=f"target '{target.name}' should be declared .PHONY if it does not produce a file",
                        path=rel,
                        lineno=0,
                        line=target.name,
                    )
                )

        if info.targets and not info.has_phony_decl:
            named = {t.name for t in info.targets if t.has_recipe}
            if named & common_targets:
                findings.append(
                    MakefileFinding(
                        kind="no_phony_section",
                        severity="low",
                        message="Makefile defines common targets without any .PHONY declaration",
                        path=rel,
                        lineno=0,
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
.PHONY: help install test lint format clean

help:
\t@echo "Targets: install test lint format clean"

install:
\tpip install -e ".[dev]"

test:
\tpython -m pytest

lint:
\truff check .

format:
\truff format .

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
