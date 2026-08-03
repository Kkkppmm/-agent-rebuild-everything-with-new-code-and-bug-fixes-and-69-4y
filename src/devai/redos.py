"""ReDoSAnalyzer — detect regex patterns vulnerable to catastrophic backtracking."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_RE_FUNCS = frozenset({"compile", "match", "search", "sub", "subn", "findall", "finditer", "split", "fullmatch"})

# Nested or overlapping quantifiers that often cause catastrophic backtracking.
_REDOS_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\([^)]*[+*?][^)]*\)[+*?]"), "nested_quantifier", "Nested quantifiers in regex group"),
    (re.compile(r"\(\.\*\)[+*]"), "dot_star_repeat", "Repeated .* group — classic ReDoS pattern"),
    (re.compile(r"\(\.\+\)[+*]"), "dot_plus_repeat", "Repeated .+ group — classic ReDoS pattern"),
    (re.compile(r"\([^)]*\|[^)]*\)[+*?]{2,}"), "alternation_quantifier", "Alternation with repeated quantifiers"),
    (re.compile(r"\([^)]*[+*?]\)[+*?]\{"), "nested_quantifier_brace", "Nested quantifiers with brace repetition"),
)


@dataclass
class ReDoSFinding:
    """A regex pattern that may be vulnerable to ReDoS."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    regex_snippet: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        snippet = f" pattern={self.regex_snippet!r}" if self.regex_snippet else ""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.pattern}{snippet}: "
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


def _check_pattern_text(pattern: str) -> list[tuple[str, str, str]]:
    """Return list of (pattern_type, severity, message) for risky regex text."""
    hits: list[tuple[str, str, str]] = []
    for compiled, pattern_type, message in _REDOS_PATTERNS:
        if compiled.search(pattern):
            severity = "high" if pattern_type in {"dot_star_repeat", "dot_plus_repeat"} else "medium"
            hits.append((pattern_type, severity, message))
    return hits


def _string_from_node(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _ReDoSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect risky regex patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ReDoSFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern_type: str,
        *,
        severity: str,
        message: str,
        regex_snippet: str = "",
    ) -> None:
        self.findings.append(
            ReDoSFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern_type,
                severity=severity,
                message=message,
                regex_snippet=regex_snippet[:80],
            )
        )

    def _check_regex_string(self, node: ast.AST, pattern: str) -> None:
        for pattern_type, severity, message in _check_pattern_text(pattern):
            self._add(
                node,
                pattern_type,
                severity=severity,
                message=message,
                regex_snippet=pattern,
            )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _RE_FUNCS:
            module = None
            if isinstance(func.value, ast.Name):
                module = func.value.id
            if module == "re" and node.args:
                pattern = _string_from_node(node.args[0])
                if pattern:
                    self._check_regex_string(node, pattern)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name) and (
                    "regex" in target.id.lower() or "pattern" in target.id.lower()
                ):
                    self._check_regex_string(node, node.value.value)
        self.generic_visit(node)


class ReDoSAnalyzer:
    """Detect regex patterns that may cause catastrophic backtracking (ReDoS).

    Flags nested quantifiers, repeated ``(.*)`` / ``(.+)`` groups, and similar
    patterns in ``re.compile``, ``re.match``, ``re.search``, and related calls.
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
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            visitor = _ReDoSVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

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
        """Return a 0-100 health score (100 = no risky regex patterns)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 8.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"ReDoS: {stats.total_findings} risky patterns in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing ReDoS findings."""
        self.analyze()
        lines = [
            "ReDoS analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No risky regex patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
