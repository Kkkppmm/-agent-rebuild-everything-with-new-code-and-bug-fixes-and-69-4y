"""NoSQLInjectionAnalyzer — detect dynamic NoSQL query construction patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_NOSQL_METHODS = frozenset({
    "find",
    "find_one",
    "find_one_and_update",
    "find_one_and_replace",
    "find_one_and_delete",
    "update_one",
    "update_many",
    "delete_one",
    "delete_many",
    "aggregate",
    "count_documents",
    "distinct",
    "insert_one",
    "insert_many",
    "replace_one",
})
_WHERE_OPERATORS = frozenset({"$where", "$regex"})
_DYNAMIC_QUERY_PATTERNS = frozenset({"f_string", "concatenation", "format", "eval_filter"})


@dataclass
class NoSQLInjectionFinding:
    """A potentially unsafe NoSQL query construction pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class NoSQLInjectionStats:
    """Aggregate NoSQL injection analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _contains_dynamic_value(node: ast.AST) -> tuple[str, str, str] | None:
    """Return (pattern, severity, message) if node builds a query dynamically."""
    if isinstance(node, ast.JoinedStr):
        return ("f_string", "high", "NoSQL query built with f-string — use parameterized filters")
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return (
            "concatenation",
            "high",
            "NoSQL query built via string concatenation — use structured query dicts",
        )
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            if node.args or node.keywords:
                return (
                    "format",
                    "high",
                    "NoSQL query built with str.format() — use structured query dicts",
                )
    return None


def _dict_has_where_operator(node: ast.AST) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for key in node.keys:
        if isinstance(key, ast.Constant) and str(key.value) in _WHERE_OPERATORS:
            return True
    return False


def _is_nosql_call(node: ast.Call) -> bool:
    return _call_name(node) in _NOSQL_METHODS


class _NoSQLInjectionVisitor(ast.NodeVisitor):
    """Walk a module AST and collect NoSQL injection risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[NoSQLInjectionFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        *,
        pattern: str,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            NoSQLInjectionFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
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
        if _is_nosql_call(node) and node.args:
            for arg in node.args:
                result = _contains_dynamic_value(arg)
                if result:
                    pattern, severity, message = result
                    self._add(node, pattern=pattern, severity=severity, message=message)
                if _dict_has_where_operator(arg):
                    self._add(
                        node,
                        pattern="where_operator",
                        severity="critical",
                        message="$where or $regex with dynamic input allows server-side JS injection",
                    )

        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "eval":
            self._add(
                node,
                pattern="eval_filter",
                severity="critical",
                message="MongoDB $expr or eval-style filter — never evaluate user input",
            )

        self.generic_visit(node)


class NoSQLInjectionAnalyzer:
    """Detect dynamic NoSQL query construction in MongoDB-style calls.

    Flags f-strings, concatenation, and formatting used to build queries
    passed to find(), update(), aggregate(), and similar methods.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[NoSQLInjectionFinding] = []
        self._stats: NoSQLInjectionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[NoSQLInjectionFinding]:
        """Analyze the project and return NoSQL injection findings."""
        if self._findings:
            return self._findings

        findings: list[NoSQLInjectionFinding] = []
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
            visitor = _NoSQLInjectionVisitor(rel)
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

        self._stats = NoSQLInjectionStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> NoSQLInjectionStats:
        """Return aggregate NoSQL injection statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[NoSQLInjectionFinding]:
        """Return critical and high severity findings."""
        return [f for f in self.analyze() if f.severity in {"critical", "high"}]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no NoSQL injection risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = critical * 40.0 + high * 25.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        critical = stats.by_severity.get("critical", 0)
        high = stats.by_severity.get("high", 0)
        lines = [
            f"NoSQL injection: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Critical: {critical}, High: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing NoSQL injection findings."""
        self.analyze()
        lines = [
            "NoSQL injection analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No NoSQL injection risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
