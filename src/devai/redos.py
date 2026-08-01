"""ReDoSAnalyzer — detect regex patterns vulnerable to catastrophic backtracking."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_RE_MODULE_ATTRS = frozenset({"compile", "match", "search", "fullmatch", "findall", "sub", "split"})
_NESTED_QUANTIFIER_RE = re.compile(
    r"(?:\([^)]*[+*?][^)]*\))[+*?]"
    r"|(?:\[[^\]]*[+*?][^\]]*\])[+*?]"
    r"|(?:\([^)]*\|[^)]*\))[+*?]{2,}"
)
_OVERLAPPING_ALTERNATION_RE = re.compile(r"\([^)]*\|[^)]*\)\+")
_DANGEROUS_PATTERNS = (
    (_NESTED_QUANTIFIER_RE, "nested_quantifier", "high", "Nested quantifiers can cause catastrophic backtracking"),
    (_OVERLAPPING_ALTERNATION_RE, "overlapping_alternation", "medium", "Overlapping alternation with quantifiers may cause ReDoS"),
)


@dataclass
class ReDoSFinding:
    """A regex pattern potentially vulnerable to ReDoS."""

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
        regex_preview = self.regex[:60] + ("..." if len(self.regex) > 60 else "")
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message} — `{regex_preview}`"


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


def _analyze_regex_string(regex: str) -> list[tuple[str, str, str]]:
    findings: list[tuple[str, str, str]] = []
    for pattern_re, pattern_name, severity, message in _DANGEROUS_PATTERNS:
        if pattern_re.search(regex):
            findings.append((pattern_name, severity, message))
    return findings


class _ReDoSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect ReDoS-vulnerable regex patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ReDoSFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add_regex_findings(self, node: ast.AST, regex: str) -> None:
        for pattern_name, severity, message in _analyze_regex_string(regex):
            self.findings.append(
                ReDoSFinding(
                    path=self.path,
                    lineno=getattr(node, "lineno", 0),
                    pattern=pattern_name,
                    severity=severity,
                    message=message,
                    regex=regex,
                    function=self._current_function(),
                )
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            module = _module_name(func.value)
            if module and module.split(".")[0] == "re" and func.attr in _RE_MODULE_ATTRS:
                if node.args:
                    regex = _string_value(node.args[0])
                    if regex:
                        self._add_regex_findings(node, regex)
        self.generic_visit(node)


class ReDoSAnalyzer:
    """Detect regex patterns vulnerable to regular expression denial of service.

    Flags nested quantifiers, overlapping alternations, and other patterns
    that can cause exponential backtracking on crafted input.
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

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no ReDoS risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 15.0 + medium * 8.0
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
            "ReDoS analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No ReDoS-vulnerable regex patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
