"""SQLInjectionAnalyzer — detect string interpolation in SQL queries."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_EXECUTE_NAMES = frozenset(
    {
        "execute",
        "executemany",
        "raw",
        "execute_sql",
        "run_sql",
        "query",
        "raw_query",
    }
)

_SQL_KEYWORDS = frozenset(
    {
        "select",
        "insert",
        "update",
        "delete",
        "create",
        "drop",
        "alter",
        "truncate",
        "merge",
        "replace",
        "with",
    }
)


@dataclass
class SQLInjectionRisk:
    """A potential SQL injection risk in Python source."""

    path: str
    function: str
    lineno: int
    call_name: str
    pattern: str
    severity: str
    message: str

    def format(self) -> str:
        """Return a single-line description."""
        location = f"{self.function}()" if self.function else "<module>"
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.pattern}: "
            f"{location} calls {self.call_name} — {self.message}"
        )


@dataclass
class SQLInjectionStats:
    """Aggregate SQL injection risk statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_scanned: int = 0
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _looks_like_sql(text: str) -> bool:
    stripped = text.strip().lower()
    if not stripped:
        return False
    first = stripped.split(None, 1)[0] if stripped.split() else ""
    return first in _SQL_KEYWORDS


def _constant_sql_prefix(node: ast.expr) -> str | None:
    """Return a SQL-like prefix from a constant string node, if any."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def _has_interpolation(node: ast.expr) -> bool:
    """Return True if the expression builds SQL via interpolation or concatenation."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in node.values)

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if _is_all_constant_strings(node):
            return False
        return True

    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name == "format":
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"replace", "join"}:
            return True

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True

    return False


def _is_all_constant_strings(node: ast.expr) -> bool:
    """Return True if an expression is only constant string literals joined with +."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_all_constant_strings(node.left) and _is_all_constant_strings(node.right)
    return False


def _pattern_for(node: ast.expr) -> str:
    if isinstance(node, ast.JoinedStr):
        return "f_string"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return "concatenation"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return "percent_format"
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name == "format" or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "format"
        ):
            return "str_format"
    return "dynamic_sql"


def _risk_from_arg(
    arg: ast.expr,
    *,
    path: str,
    function: str,
    lineno: int,
    call_name: str,
) -> SQLInjectionRisk | None:
    if not _has_interpolation(arg):
        return None

    prefix = _constant_sql_prefix(arg)
    if prefix is not None and not _looks_like_sql(prefix):
        return None

    pattern = _pattern_for(arg)
    severity = "high" if pattern in {"f_string", "percent_format", "concatenation"} else "medium"
    messages = {
        "f_string": "f-string SQL — use parameterized queries with placeholders",
        "concatenation": "SQL built with + concatenation — use parameterized queries",
        "percent_format": "% formatting in SQL — use parameterized queries",
        "str_format": ".format() in SQL — use parameterized queries",
        "dynamic_sql": "dynamic SQL construction — verify parameterization",
    }
    return SQLInjectionRisk(
        path=path,
        function=function,
        lineno=lineno,
        call_name=call_name,
        pattern=pattern,
        severity=severity,
        message=messages.get(pattern, messages["dynamic_sql"]),
    )


class _SQLInjectionVisitor(ast.NodeVisitor):
    """Walk a module AST and collect SQL injection risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[SQLInjectionRisk] = []
        self._function_stack: list[str] = []

    @property
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

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name in _EXECUTE_NAMES and node.args:
            risk = _risk_from_arg(
                node.args[0],
                path=self.path,
                function=self._current_function,
                lineno=getattr(node, "lineno", 1),
                call_name=name,
            )
            if risk:
                self.findings.append(risk)
        self.generic_visit(node)


class SQLInjectionAnalyzer:
    """Detect SQL injection risks from string interpolation in query execution.

    Flags f-strings, concatenation, ``%`` formatting, and ``.format()`` used
  in common database ``execute``-style calls when the query looks like SQL.
  """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        include_tests: bool = False,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.include_tests = include_tests
        self._findings: list[SQLInjectionRisk] = []
        self._stats: SQLInjectionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        if path.suffix != ".py":
            return True
        if not self.include_tests:
            parts = set(path.parts)
            if parts & {"tests", "test", "testing"}:
                return True
            if path.name.startswith("test_") or path.name.endswith("_test.py"):
                return True
        return False

    def analyze(self) -> list[SQLInjectionRisk]:
        """Analyze the project and return SQL injection risks."""
        if self._findings:
            return self._findings

        findings: list[SQLInjectionRisk] = []
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
            visitor = _SQLInjectionVisitor(rel)
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

        self._stats = SQLInjectionStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_scanned=files_scanned,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> SQLInjectionStats:
        """Return aggregate SQL injection statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[SQLInjectionRisk]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no SQL injection risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"SQL injection risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({stats.files_scanned} files scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing SQL injection risks."""
        self.analyze()
        lines = [
            "SQL injection risk analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No SQL injection risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
