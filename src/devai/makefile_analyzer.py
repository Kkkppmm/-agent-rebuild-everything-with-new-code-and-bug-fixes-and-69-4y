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
RM_RF_ROOT_PATTERN = re.compile(r"rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?/?\s*$", re.IGNORECASE)
RM_RF_DANGEROUS_PATTERN = re.compile(
    r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?(/|\$\{|~|\$\(HOME\)|\$\(PWD\))",
    re.IGNORECASE,
)
CHMOD_777_PATTERN = re.compile(r"chmod\s+777\b", re.IGNORECASE)
SECRET_ASSIGN_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['\"]?[^\s'\"#]{4,}",
    re.IGNORECASE,
)
FORCE_PUSH_PATTERN = re.compile(r"git\s+push\s+[^\n]*--force\b", re.IGNORECASE)
DOCKER_PRIVILEGED_PATTERN = re.compile(r"docker\s+run\b[^\n]*--privileged\b", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"\beval\s+", re.IGNORECASE)
CURL_INSECURE_PATTERN = re.compile(r"curl\s+[^\n]*\s(-k|--insecure)\b", re.IGNORECASE)
UNPINNED_PIP_PATTERN = re.compile(
    r"pip\s+install\b(?![^\n]*(?:==|@|~=|<=|>=|<|>))[^\n]*\b[a-zA-Z0-9][a-zA-Z0-9._-]*\b",
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
    has_clean: bool = False
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
    if name in MAKEFILE_NAMES:
        return True
    if lower.endswith(".mk"):
        return True
    if lower.endswith("makefile") and "." in name:
        return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for curl-pipe-to-shell patterns, dangerous ``rm -rf`` targets,
  secrets in variable assignments, force-push git commands, privileged
    Docker runs, and other common Makefile misconfigurations.
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

            if line.startswith(".PHONY:"):
                info.has_phony = True
                for target in line.split(":", 1)[1].split():
                    if target and target not in info.targets:
                        info.targets.append(target)

            if re.match(r"^[a-zA-Z0-9_.-]+:", line) and not line.startswith("."):
                current_target = line.split(":", 1)[0].strip()
                if current_target and current_target not in info.targets:
                    info.targets.append(current_target)
                if current_target == "clean":
                    info.has_clean = True

            def add(kind: str, severity: str, message: str) -> None:
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

            if CURL_PIPE_SHELL_PATTERN.search(line):
                add(
                    "curl_pipe_shell",
                    "high",
                    "piping curl/wget to shell is unsafe",
                )

            if SUDO_PATTERN.search(line):
                add(
                    "sudo_usage",
                    "medium",
                    "sudo in Makefile recipes — prefer non-root build steps",
                )

            if RM_RF_ROOT_PATTERN.search(line) or RM_RF_DANGEROUS_PATTERN.search(line):
                add(
                    "dangerous_rm",
                    "high",
                    "dangerous rm -rf pattern — risk of deleting system or home directories",
                )

            if CHMOD_777_PATTERN.search(line):
                add(
                    "chmod_777",
                    "medium",
                    "chmod 777 grants world-writable permissions",
                )

            if SECRET_ASSIGN_PATTERN.search(line):
                add(
                    "secret_in_variable",
                    "high",
                    "potential secret in Makefile variable — use env files or CI secrets",
                )

            if FORCE_PUSH_PATTERN.search(line):
                add(
                    "git_force_push",
                    "high",
                    "git push --force can overwrite remote history",
                )

            if DOCKER_PRIVILEGED_PATTERN.search(line):
                add(
                    "docker_privileged",
                    "high",
                    "docker run --privileged grants excessive container permissions",
                )

            if EVAL_PATTERN.search(line):
                add(
                    "eval_usage",
                    "medium",
                    "eval executes arbitrary shell — avoid in Makefiles",
                )

            if CURL_INSECURE_PATTERN.search(line):
                add(
                    "curl_insecure",
                    "medium",
                    "curl -k/--insecure disables TLS certificate verification",
                )

            if UNPINNED_PIP_PATTERN.search(line):
                add(
                    "unpinned_pip",
                    "low",
                    "pip install without version pin — pin dependencies for reproducibility",
                )

        if info.targets and not info.has_phony:
            findings.append(
                MakefileFinding(
                    kind="missing_phony",
                    severity="low",
                    message="no .PHONY declaration — file targets may conflict with build artifacts",
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
        target_count = sum(len(i.targets) for i in infos)
        self._stats = MakefileStats(
            makefiles=len(paths),
            findings=len(findings),
            targets=target_count,
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
.PHONY: install test lint clean

PYTHON ?= python3
VENV ?= .venv

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
                f"phony={'yes' if info.has_phony else 'no'}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
