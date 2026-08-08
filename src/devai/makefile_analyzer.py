"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAKEFILE_NAMES = ("Makefile", "makefile", "GNUmakefile")

DANGEROUS_RM_PATTERN = re.compile(r"rm\s+(-[^\s]*r[^\s]*\s+|.*\s+-[^\s]*r)\s*/\s*$|rm\s+-rf\s+/\s")
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token)\s*[:=]\s*['\"]?\w+",
    re.IGNORECASE,
)
COMMON_TARGETS = ("clean", "install", "test", "build", "lint", "format", "run", "deploy")


@dataclass
class MakefileFinding:
    """A security or best-practice issue in a Makefile."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""
    target: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f" ({self.target})" if self.target else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{loc} — {self.message}"


@dataclass
class MakefileTargetInfo:
    """Parsed metadata about a Makefile target."""

    name: str
    is_phony: bool = False
    lines: int = 0


@dataclass
class MakefileStats:
    """Aggregate Makefile analysis statistics."""

    makefiles: int
    targets: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_makefile(path: Path) -> bool:
    return path.name in MAKEFILE_NAMES or path.name.endswith(".mk")


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class MakefileAnalyzer:
    """Audit Makefiles for dangerous commands and build hygiene.

    Scans for destructive rm commands, sudo usage, curl-pipe-to-shell,
    hardcoded secrets, and missing .PHONY declarations.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MakefileFinding] | None = None
        self._stats: MakefileStats | None = None
        self._targets: list[MakefileTargetInfo] | None = None

    def makefiles(self) -> list[Path]:
        """Return Makefile paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_makefile(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[MakefileFinding], list[MakefileTargetInfo]]:
        findings: list[MakefileFinding] = []
        targets: list[MakefileTargetInfo] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, targets

        phony_targets: set[str] = set()
        current_target: MakefileTargetInfo | None = None

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            if line.startswith(".PHONY:"):
                for name in line.split(":", 1)[1].split():
                    phony_targets.add(name.strip())
                continue

            if re.match(r"^[\w.-]+:", line) and not line.startswith("\t"):
                target_name = line.split(":", 1)[0].strip()
                if target_name and not target_name.startswith("."):
                    current_target = MakefileTargetInfo(name=target_name)
                    targets.append(current_target)
                continue

            if current_target:
                current_target.lines += 1

            if DANGEROUS_RM_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="dangerous_rm",
                        severity="high",
                        message="destructive rm command — risk of deleting system files",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                        target=current_target.name if current_target else "",
                    )
                )

            if SUDO_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="sudo_usage",
                        severity="medium",
                        message="sudo in Makefile — prefer non-privileged commands",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                        target=current_target.name if current_target else "",
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
                        target=current_target.name if current_target else "",
                    )
                )

            if SECRET_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="potential hardcoded secret in Makefile",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                        target=current_target.name if current_target else "",
                    )
                )

            if "rm -rf" in line and "$" not in line and "*" in line:
                findings.append(
                    MakefileFinding(
                        kind="unquoted_glob_rm",
                        severity="medium",
                        message="rm -rf with glob — ensure target path is intentional",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                        target=current_target.name if current_target else "",
                    )
                )

        for target in targets:
            if target.name in phony_targets:
                target.is_phony = True
            elif target.name in COMMON_TARGETS:
                findings.append(
                    MakefileFinding(
                        kind="missing_phony",
                        severity="low",
                        message=f"target '{target.name}' should be declared .PHONY",
                        path=rel,
                        lineno=1,
                        line="",
                        target=target.name,
                    )
                )

        return findings, targets

    def analyze(self) -> list[MakefileFinding]:
        """Scan Makefiles and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MakefileFinding] = []
        all_targets: list[MakefileTargetInfo] = []
        paths = self.makefiles()

        for path in paths:
            file_findings, targets = self._analyze_file(path)
            findings.extend(file_findings)
            all_targets.extend(targets)

        self._findings = findings
        self._targets = all_targets
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = MakefileStats(
            makefiles=len(paths),
            targets=len(all_targets),
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
    def targets(self) -> list[MakefileTargetInfo]:
        """Return parsed target metadata."""
        if self._targets is None:
            self.analyze()
        return self._targets  # type: ignore[return-value]

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

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.makefiles == 0:
            return "Makefiles: none found"
        return (
            f"Makefiles: {stats.makefiles} file(s), {stats.targets} target(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
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
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
