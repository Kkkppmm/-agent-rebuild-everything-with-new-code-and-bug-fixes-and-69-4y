"""SQLInjectionAnalyzer — detect dynamic SQL construction patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_EXECUTE_ATTRS = frozenset({"execute", "executemany", "executescript", "raw"})
_SQL_KEYWORDS = frozenset(
    {"select", "insert", "update", "delete", "drop", "create", "alter", "truncate"}
)


@dataclass
class SQLInjectionFinding:
    """A potentially unsafe SQL construction pattern."""

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
class SQLInjectionStats:
    """Aggregate SQL injection analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_sql_string(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        text = node.value.strip().lower()
        return any(text.startswith(kw) for kw in _SQL_KEYWORDS)
    return False


def _contains_dynamic_sql(node: ast.AST) -> tuple[str, str, str] | None:
    """Return (pattern, severity, message) if node builds SQL dynamically."""
    if isinstance(node, ast.JoinedStr):
        return ("f_string", "high", "SQL built with f-string — use parameterized queries")
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_dynamic = _is_sql_string(node.left) or _contains_dynamic_sql(node.left) is not None
        right_dynamic = _is_sql_string(node.right) or _contains_dynamic_sql(node.right) is not None
        if left_dynamic or right_dynamic:
            return (
                "concatenation",
                "high",
                "SQL built via string concatenation — use parameterized queries",
            )
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            if node.args or node.keywords:
                return ("format", "high", "SQL built with str.format() — use parameterized queries")
        if isinstance(func, ast.Attribute) and func.attr == "join":
            if node.args:
                return (
                    "join",
                    "medium",
                    "SQL built with str.join() — verify inputs are sanitized",
                )
    return None


def _is_execute_call(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    return node.func.attr in _EXECUTE_ATTRS


class _SQLInjectionVisitor(ast.NodeVisitor):
    """Walk a module AST and collect SQL injection risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[SQLInjectionFinding] = []
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

    def visit_Call(self, node: ast.Call) -> None:
        if _is_execute_call(node) and node.args:
            sql_arg = node.args[0]
            result = _contains_dynamic_sql(sql_arg)
            if result:
                pattern, severity, message = result
                self.findings.append(
                    SQLInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern=pattern,
                        severity=severity,
                        message=message,
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class SQLInjectionAnalyzer:
    """Detect dynamic SQL construction in execute() calls.

    Flags f-strings, concatenation, and formatting used to build SQL
  passed to database execute methods.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[SQLInjectionFinding] = []
        self._stats: SQLInjectionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[SQLInjectionFinding]:
        """Analyze the project and return SQL injection findings."""
        if self._findings:
            return self._findings

        findings: list[SQLInjectionFinding] = []
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
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> SQLInjectionStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[SQLInjectionFinding]:
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
        lines = [
            f"SQL injection risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing SQL injection findings."""
        self.analyze()
        lines = [
            "SQL injection analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No dynamic SQL construction found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
