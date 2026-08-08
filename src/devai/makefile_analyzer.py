"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAKEFILE_NAMES = ("Makefile", "makefile", "GNUmakefile")

RM_RF_ROOT_PATTERN = re.compile(
    r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?/\s*$",
    re.IGNORECASE,
)
RM_RF_HOME_PATTERN = re.compile(r"rm\s+[^\n]*\$(HOME|~)", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"chmod\s+777\b", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
FORCE_PUSH_PATTERN = re.compile(r"git\s+push\s+[^\n]*--force", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"\beval\s+", re.IGNORECASE)
CURL_INSECURE_PATTERN = re.compile(r"curl\s+[^\n]*(-k|--insecure)\b", re.IGNORECASE)


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
    return path.name in MAKEFILE_NAMES or path.suffix.lower() in (".mk",)


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for destructive rm commands, sudo usage, chmod 777, curl-pipe-to-shell,
    hardcoded secrets, force-push targets, and eval usage.
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

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            if line.startswith(".PHONY:"):
                info.has_phony = True
                for target in line[7:].split():
                    if target:
                        info.targets.append(target)

            if re.match(r"^[a-zA-Z0-9_.-]+:", line) and not line.startswith("."):
                target = line.split(":", 1)[0].strip()
                if target and target not in info.targets:
                    info.targets.append(target)

            if RM_RF_ROOT_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="rm_rf_root",
                        severity="high",
                        message="rm targeting filesystem root — extremely destructive",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if RM_RF_HOME_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="rm_rf_home",
                        severity="high",
                        message="rm targeting $HOME — can delete user data",
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
                        message="sudo in Makefile — avoid requiring elevated privileges in build scripts",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CHMOD_777_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="chmod_777",
                        severity="high",
                        message="chmod 777 grants world-writable permissions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
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

            if SECRET_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="secret_in_makefile",
                        severity="high",
                        message="potential secret in Makefile — use environment variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FORCE_PUSH_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="force_push",
                        severity="medium",
                        message="git push --force in Makefile — risky in shared workflows",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EVAL_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="eval_usage",
                        severity="medium",
                        message="eval in Makefile — avoid executing dynamic shell strings",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_INSECURE_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="curl_insecure",
                        severity="medium",
                        message="curl with -k/--insecure disables TLS verification",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if info.targets and not info.has_phony:
            findings.append(
                MakefileFinding(
                    kind="missing_phony",
                    severity="low",
                    message="no .PHONY declaration — add .PHONY for non-file targets",
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
        """Scaffold a hardened Makefile template."""
        return """\
# Generated by DevAI MakefileAnalyzer
.PHONY: install test lint clean

install:
\tpip install -e ".[dev]"

test:
\tpython -m pytest

lint:
\truff check src tests

clean:
\trm -rf .pytest_cache .ruff_cache dist build *.egg-info
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
        stats = self.stats
        lines = [
            "Makefile analysis:",
            f"  makefiles: {stats.makefiles}",
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
