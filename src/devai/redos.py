"""ReDoSAnalyzer — detect regex patterns vulnerable to catastrophic backtracking."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_RE_ATTRS = frozenset(
    {
        "compile",
        "match",
        "search",
        "fullmatch",
        "findall",
        "finditer",
        "sub",
        "subn",
        "split",
    }
)
_RE_MODULES = frozenset({"re", "regex"})

# Group with internal quantifier followed by outer quantifier: (a+)+, (a*)*, etc.
_NESTED_QUANTIFIER = re.compile(
    r"\([^()\\]*(?:\\.[^()\\]*)*[+*?{][^()\\]*(?:\\.[^()\\]*)*\)[+*?{]"
)
# (.+)+ or (.*)+ style patterns
_DOT_QUANTIFIER = re.compile(r"\(\.\*[^)]*\)[+*{]|\(\.\+[^)]*\)[+*{]")
# Overlapping alternation: (foo|foo)+
_OVERLAPPING_ALT = re.compile(
    r"\(([^|()\\]+(?:\\.[^|()\\]*)*)\|\1\)[+*?{]"
)
# Adjacent duplicate alternation branches with quantifier on group
_DUPLICATE_BRANCH = re.compile(
    r"\(([^|()\\]+)\|([^|()\\]+)\)[+*?{]"
)


@dataclass
class ReDoSFinding:
    """A potentially vulnerable regular expression pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    regex: str = ""
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        preview = self.regex[:60] + ("..." if len(self.regex) > 60 else "")
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message} — `{preview}`"


@dataclass
class ReDoSStats:
    """Aggregate ReDoS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _module_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _module_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _classify_regex(pattern: str) -> list[tuple[str, str, str]]:
    """Return list of (pattern_id, severity, message) for a regex string."""
    findings: list[tuple[str, str, str]] = []

    if _NESTED_QUANTIFIER.search(pattern):
        findings.append(
            (
                "nested_quantifier",
                "high",
                "Nested quantifiers can cause catastrophic backtracking (ReDoS)",
            )
        )

    if _DOT_QUANTIFIER.search(pattern):
        findings.append(
            (
                "dot_star_quantifier",
                "high",
                "Quantified dot-star/plus groups are a common ReDoS vector",
            )
        )

    if _OVERLAPPING_ALT.search(pattern):
        findings.append(
            (
                "overlapping_alternation",
                "medium",
                "Overlapping alternation branches amplify backtracking cost",
            )
        )
    else:
        match = _DUPLICATE_BRANCH.search(pattern)
        if match and match.group(1) == match.group(2):
            findings.append(
                (
                    "duplicate_alternation",
                    "medium",
                    "Duplicate alternation branches with quantifier may cause ReDoS",
                )
            )

    # Long patterns with multiple nested groups and quantifiers
    if len(pattern) > 80 and pattern.count("(") >= 3 and any(ch in pattern for ch in "+*{"):
        if not findings:
            findings.append(
                (
                    "complex_pattern",
                    "low",
                    "Complex regex with multiple quantifiers — review for ReDoS risk",
                )
            )

    return findings


class _ReDoSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect risky regex patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ReDoSFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def _record_pattern(self, regex: str, lineno: int) -> None:
        for pattern_id, severity, message in _classify_regex(regex):
            self.findings.append(
                ReDoSFinding(
                    path=self.path,
                    lineno=lineno,
                    pattern=pattern_id,
                    severity=severity,
                    message=message,
                    regex=regex,
                    function=self._current_function(),
                )
            )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _RE_ATTRS:
            module = _module_name(func.value)
            base = module.split(".")[0] if module else ""
            if base in _RE_MODULES or (module and module in _RE_MODULES):
                if node.args:
                    regex = _string_value(node.args[0])
                    if regex:
                        self._record_pattern(regex, node.lineno)
        self.generic_visit(node)


class ReDoSAnalyzer:
    """Detect regular expressions vulnerable to ReDoS in Python projects.

    Flags nested quantifiers, quantified dot-star/plus groups, overlapping
    alternation, and other patterns that can cause catastrophic backtracking.
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
        """Return aggregate statistics."""
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
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 25.0 + medium * 15.0 + low * 5.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"ReDoS: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing ReDoS findings."""
        self.analyze()
        lines = [
            "ReDoS (regex denial-of-service) analysis:",
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
