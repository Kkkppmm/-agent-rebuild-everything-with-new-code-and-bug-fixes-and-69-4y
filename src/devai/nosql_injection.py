"""NoSQLInjectionAnalyzer — detect dynamic NoSQL query construction."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_QUERY_ATTRS = frozenset(
    {
        "find",
        "find_one",
        "findOne",
        "aggregate",
        "update",
        "update_one",
        "updateOne",
        "delete",
        "delete_one",
        "deleteOne",
        "insert",
        "insert_one",
        "insertOne",
        "count_documents",
        "countDocuments",
    }
)
_DYNAMIC_BUILDERS = frozenset({"format", "join"})


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
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class NoSQLInjectionStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_dynamic_query(node: ast.AST) -> tuple[str, str, str] | None:
    if isinstance(node, ast.JoinedStr):
        return ("f_string", "high", "NoSQL query built with f-string — use parameterized filters")
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return ("concatenation", "high", "NoSQL query built via string concatenation")
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in _DYNAMIC_BUILDERS:
            return ("format", "high", "NoSQL query built with dynamic string formatting")
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if key is None:
                continue
            if isinstance(key, ast.Constant) and key.value in {"$where", "$regex"}:
                if not isinstance(value, ast.Constant):
                    return ("operator_injection", "high", "Dynamic value in $where/$regex operator")
    return None


def _is_query_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr in _QUERY_ATTRS
    return False


class _NoSQLInjectionVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[NoSQLInjectionFinding] = []
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
        if _is_query_call(node) and node.args:
            result = _is_dynamic_query(node.args[0])
            if result:
                pattern, severity, message = result
                self.findings.append(
                    NoSQLInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern=pattern,
                        severity=severity,
                        message=message,
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class NoSQLInjectionAnalyzer:
    """Detect dynamic NoSQL query construction in MongoDB/Motor/PyMongo code."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
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

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 25.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"NoSQL injection risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["NoSQL injection analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No dynamic NoSQL query patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
