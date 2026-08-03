"""ReDoSAnalyzer — detect catastrophic backtracking regex patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

# Nested quantifiers and overlapping alternation patterns prone to ReDoS
_REDOS_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "nested_quantifier",
        re.compile(r"\([^)]*[+*?][^)]*\)[+*?{]"),
        "high",
        "Nested quantifier can cause catastrophic backtracking",
    ),
    (
        "overlapping_alternation",
        re.compile(r"\([^|)]*\|[^|)]*\)[+*]"),
        "high",
        "Overlapping alternation with quantifier risks exponential backtracking",
    ),
    (
        "greedy_wildcard_loop",
        re.compile(r"\(\.\*\)[+*]|\(\.\+\)[+*]"),
        "high",
        "Greedy wildcard inside quantified group causes ReDoS",
    ),
    (
        "adjacent_quantifiers",
        re.compile(r"[+*?]{2,}"),
        "medium",
        "Adjacent quantifiers may cause excessive backtracking",
    ),
    (
        "unbounded_repeat",
        re.compile(r"\([^)]*\)\{[0-9]+,\}"),
        "medium",
        "Unbounded repetition range can cause slow matching on long inputs",
    ),
]


@dataclass
class ReDoSFinding:
    """A regex pattern vulnerable to catastrophic backtracking."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    regex: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        rx = f" regex={self.regex!r}" if self.regex else ""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.pattern}{rx}: "
            f"{self.message}"
        )


@dataclass
class ReDoSStats:
    """Aggregate ReDoS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _extract_regex_literals(source: str) -> list[tuple[int, str]]:
    """Extract regex string literals and their line numbers."""
    results: list[tuple[int, str]] = []
    lines = source.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for match in re.finditer(r"""re\.(?:compile\s*\()?\s*['"]([^'"]+)['"]""", line):
            results.append((lineno, match.group(1)))
        for match in re.finditer(r"""r['"]([^'"]+)['"]""", line):
            if "re." in line or "compile" in line or "match" in line or "search" in line:
                results.append((lineno, match.group(1)))
    return results


class ReDoSAnalyzer:
    """Detect regex patterns vulnerable to catastrophic backtracking (ReDoS).

    Flags nested quantifiers, overlapping alternations, and greedy wildcard
    loops in ``re.compile()`` and inline regex literals.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[ReDoSFinding] = []
        self._stats: ReDoSStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _check_pattern(self, lineno: int, regex: str, rel: str) -> list[ReDoSFinding]:
        findings: list[ReDoSFinding] = []
        for pattern_name, compiled, severity, message in _REDOS_PATTERNS:
            if compiled.search(regex):
                findings.append(
                    ReDoSFinding(
                        path=rel,
                        lineno=lineno,
                        pattern=pattern_name,
                        severity=severity,
                        message=message,
                        regex=regex[:80],
                    )
                )
        return findings

    def analyze(self) -> list[ReDoSFinding]:
        """Analyze the project and return ReDoS findings."""
        if self._findings:
            return self._findings

        findings: list[ReDoSFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            for lineno, regex in _extract_regex_literals(source):
                file_findings = self._check_pattern(lineno, regex, rel)
                if file_findings:
                    files_with_findings.add(rel)
                findings.extend(file_findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = ReDoSStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> ReDoSStats:
        """Return aggregate ReDoS statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[ReDoSFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no ReDoS risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"ReDoS risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing ReDoS findings."""
        self.analyze()
        lines = ["ReDoS analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No ReDoS risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
