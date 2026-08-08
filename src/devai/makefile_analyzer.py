"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAKEFILE_NAMES = ("Makefile", "makefile", "GNUmakefile")
MAKEFILE_SUFFIXES = (".mk",)

RM_RF_ROOT_PATTERN = re.compile(r"rm\s+-[rfv]+\s+/(?:\s|$|\*)", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
CHMOD_777_PATTERN = re.compile(r"chmod\s+(-R\s+)?777\b", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\s+", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
DOCKER_PRIVILEGED_PATTERN = re.compile(
    r"docker\s+run\b[^;\n]*--privileged",
    re.IGNORECASE,
)
EVAL_CURL_PATTERN = re.compile(r"eval\s+.*\b(curl|wget)\b", re.IGNORECASE)
WILDCARD_RM_PATTERN = re.compile(r"rm\s+-[rfv]+\s+\*", re.IGNORECASE)
TARGET_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)\s*:")
PHONY_PATTERN = re.compile(r"^\.PHONY\s*:")
COMMON_PHONY_TARGETS = frozenset(
    {"all", "clean", "test", "install", "build", "run", "lint", "check", "deploy"}
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
    phony_targets: list[str] = field(default_factory=list)
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
    lower = name.lower()
    if lower.endswith(MAKEFILE_SUFFIXES):
        return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for destructive rm commands, curl-pipe-to-shell patterns, chmod 777,
    sudo usage, secrets in variable assignments, privileged docker runs, and
    missing .PHONY declarations for common targets.
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
        phony_declared: set[str] = set()

        for lineno, raw in enumerate(raw_lines, start=1):
            if raw.strip().startswith("#"):
                continue

            if PHONY_PATTERN.match(raw.strip()):
                rest = raw.strip().split(":", 1)[-1]
                for name in rest.split():
                    phony_declared.add(name)
                    if name not in info.phony_targets:
                        info.phony_targets.append(name)
                continue

            if raw and not raw.startswith(("\t", " ")):
                content = _strip_comment(raw)
                if content.endswith(":") and not content.startswith("."):
                    name = content[:-1].strip()
                    if name and " " not in name:
                        current_target = name
                        if name not in info.targets:
                            info.targets.append(name)
                        if name in COMMON_PHONY_TARGETS and name not in phony_declared:
                            findings.append(
                                MakefileFinding(
                                    kind="missing_phony",
                                    severity="low",
                                    message=f"target '{name}' should be declared in .PHONY",
                                    path=rel,
                                    lineno=lineno,
                                    target=name,
                                )
                            )
                continue

            if not raw.startswith("\t"):
                continue

            line = _strip_comment(raw)
            if not line:
                continue

            if RM_RF_ROOT_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="rm_rf_root",
                        severity="high",
                        message="rm targeting root filesystem — catastrophic if executed",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — supply-chain and injection risk",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if EVAL_CURL_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="eval_curl",
                        severity="high",
                        message="eval with curl/wget — remote code execution risk",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if DOCKER_PRIVILEGED_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="docker_privileged",
                        severity="high",
                        message="docker run --privileged grants full host capabilities",
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
                        message="sudo in recipe — prefer non-root build steps where possible",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if SECRET_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="secret_in_makefile",
                        severity="high",
                        message="possible secret or credential in Makefile variable",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=line,
                    )
                )

            if WILDCARD_RM_PATTERN.search(line) and "rm_rf_root" not in {
                f.kind for f in findings if f.lineno == lineno
            }:
                findings.append(
                    MakefileFinding(
                        kind="wildcard_rm",
                        severity="medium",
                        message="rm with wildcard — verify path before destructive cleanup",
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
.PHONY: all clean test lint

PYTHON ?= python3

all: test

test:
\t$(PYTHON) -m pytest

lint:
\t$(PYTHON) -m ruff check src tests

clean:
\tfind . -type d -name __pycache__ -exec rm -rf {} +
\tfind . -type f -name '*.pyc' -delete
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.makefiles == 0:
            return "Makefiles: none found"
        lines = [
            (
                f"Makefiles: {stats.makefiles} file(s), "
                f"{stats.findings} finding(s) "
                f"({stats.high_severity} high, {stats.medium_severity} medium, "
                f"{stats.low_severity} low)"
            ),
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self) -> str:
        """Export findings as LLM-ready context."""
        self.analyze()
        lines = [
            "# Makefile Audit",
            "",
            self.summary(),
            "",
        ]
        if self.infos:
            lines.append("## Files")
            for info in self.infos:
                targets = ", ".join(info.targets[:10]) if info.targets else "none"
                lines.append(f"- {info.path}: {len(info.targets)} target(s) [{targets}]")
            lines.append("")
        findings = self._findings or []
        if findings:
            lines.append("## Findings")
            for finding in findings[:50]:
                lines.append(f"- {finding.format()}")
            if len(findings) > 50:
                lines.append(f"- ... and {len(findings) - 50} more")
        return "\n".join(lines)
