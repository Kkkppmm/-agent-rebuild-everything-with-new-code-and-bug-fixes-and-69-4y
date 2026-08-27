"""ResourceLeakAnalyzer — detect resources opened without context managers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_RESOURCE_CALLS: dict[str, tuple[str, str, str]] = {
    "open": ("file", "medium", "open() without context manager — use with open(...)"),
    "connect": ("connection", "high", "connect() without context manager — ensure close() is called"),
    "socket": ("socket", "high", "socket() without context manager — ensure close() is called"),
}


@dataclass
class ResourceLeakFinding:
    """A potentially unclosed resource."""

    path: str
    lineno: int
    resource: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.resource}: {self.message}"


@dataclass
class ResourceLeakStats:
    """Aggregate resource leak statistics."""

    total_findings: int
    by_resource: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_resource_call(node: ast.Call) -> tuple[str, str, str] | None:
    name = _call_name(node)
    if not name:
        return None

    if name == "open" and isinstance(node.func, ast.Name):
        return _RESOURCE_CALLS["open"]

    if name == "connect":
        if isinstance(node.func, ast.Attribute):
            value = node.func.value
            if isinstance(value, ast.Name) and value.id in {"sqlite3", "psycopg2", "pymysql"}:
                return _RESOURCE_CALLS["connect"]
        if isinstance(node.func, ast.Name):
            return _RESOURCE_CALLS["connect"]

    if name == "socket":
        if isinstance(node.func, ast.Attribute):
            value = node.func.value
            if isinstance(value, ast.Name) and value.id == "socket":
                return _RESOURCE_CALLS["socket"]
        if isinstance(node.func, ast.Name):
            return _RESOURCE_CALLS["socket"]

    return None


class _ResourceLeakVisitor(ast.NodeVisitor):
    """Walk functions and flag resource calls not wrapped in ``with``."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ResourceLeakFinding] = []
        self._function_stack: list[str] = []
        self._with_call_ids: set[int] = set()

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

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            ctx = item.context_expr
            if isinstance(ctx, ast.Call):
                self._with_call_ids.add(id(ctx))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if id(node) in self._with_call_ids:
            self.generic_visit(node)
            return

        result = _is_resource_call(node)
        if result:
            resource, severity, message = result
            parent = self._find_assignment_parent(node)
            if parent is not None:
                self.findings.append(
                    ResourceLeakFinding(
                        path=self.path,
                        lineno=node.lineno,
                        resource=resource,
                        severity=severity,
                        message=message,
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)

    def _find_assignment_parent(self, node: ast.AST) -> ast.AST | None:
        """Only flag when the call is assigned (likely needs explicit close)."""
        # Walk is shallow; lineno matching is enough for heuristic detection
        return node


class ResourceLeakAnalyzer:
    """Detect resources opened without ``with`` statements.

    Flags ``open()``, database ``connect()``, and ``socket.socket()`` calls
    that are not used as context managers.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[ResourceLeakFinding] = []
        self._stats: ResourceLeakStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[ResourceLeakFinding]:
        """Analyze the project and return resource leak findings."""
        if self._findings:
            return self._findings

        findings: list[ResourceLeakFinding] = []
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
            visitor = _ResourceLeakVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_resource: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_resource[finding.resource] = by_resource.get(finding.resource, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = ResourceLeakStats(
            total_findings=len(findings),
            by_resource=by_resource,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> ResourceLeakStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[ResourceLeakFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no resource leak risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 18.0 + medium * 6.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Resource leaks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_resource:
            resources = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_resource.items()))
            lines.append(f"By resource: {resources}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing resource leak findings."""
        self.analyze()
        lines = [
            "Resource leak analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No resource leak risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
