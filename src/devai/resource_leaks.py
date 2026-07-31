"""ResourceLeakAnalyzer — detect unclosed files, sockets, and connections."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_RESOURCE_CREATORS: dict[str, tuple[str, str, str]] = {
    "open": ("file", "high", "file opened without context manager — use 'with open(...) as f'"),
    "socket": ("socket", "high", "socket created without context manager — use 'with socket.socket(...) as s'"),
    "connect": ("database", "high", "connection opened without context manager — use 'with connect(...) as conn'"),
    "TemporaryFile": ("file", "medium", "TemporaryFile without context manager may leak descriptors"),
    "NamedTemporaryFile": ("file", "medium", "NamedTemporaryFile without context manager may leak descriptors"),
}


@dataclass
class ResourceLeak:
    """A potentially unclosed resource allocation."""

    path: str
    resource: str
    lineno: int
    kind: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.function}() " if self.function else ""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.kind}: "
            f"{loc}{self.resource} — {self.message}"
        )


@dataclass
class ResourceLeakStats:
    """Aggregate resource-leak statistics."""

    total_findings: int
    by_kind: dict[str, int] = field(default_factory=dict)
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


def _call_label(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        return func.attr
    return "unknown"


def _is_sqlite_connect(node: ast.Call, name: str | None) -> bool:
    if name != "connect":
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id == "sqlite3"
    return False


def _is_socket_create(node: ast.Call, name: str | None) -> bool:
    if name != "socket":
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id == "socket"
    return False


class _ResourceLeakVisitor(ast.NodeVisitor):
    """Track resource allocations and whether they are used in with statements."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ResourceLeak] = []
        self._function_stack: list[str] = []
        self._with_targets: set[int] = set()

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        resource: str,
        kind: str,
        severity: str,
        message: str,
    ) -> None:
        lineno = getattr(node, "lineno", 1)
        self.findings.append(
            ResourceLeak(
                path=self.path,
                resource=resource,
                lineno=lineno,
                kind=kind,
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

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None and isinstance(item.context_expr, ast.Call):
                self._with_targets.add(id(item.context_expr))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            self._check_resource_call(node.value, assigned=True)
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            self._check_resource_call(node.value, assigned=False)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None and isinstance(node.value, ast.Call):
            self._check_resource_call(node.value, assigned=False)
        self.generic_visit(node)

    def _check_resource_call(self, node: ast.Call, *, assigned: bool) -> None:
        if id(node) in self._with_targets:
            return

        name = _call_name(node)
        label = _call_label(node)

        if name == "open":
            kind, severity, message = _RESOURCE_CREATORS["open"]
            self._add(node, label, kind, severity, message)
        elif _is_socket_create(node, name):
            kind, severity, message = _RESOURCE_CREATORS["socket"]
            self._add(node, label, kind, severity, message)
        elif _is_sqlite_connect(node, name):
            kind, severity, message = _RESOURCE_CREATORS["connect"]
            self._add(node, label, kind, severity, message)
        elif name in {"TemporaryFile", "NamedTemporaryFile"}:
            kind, severity, message = _RESOURCE_CREATORS[name]
            self._add(node, label, kind, severity, message)
        elif name == "connect" and isinstance(node.func, ast.Attribute):
            module = node.func.value
            if isinstance(module, ast.Name) and module.id in {"psycopg2", "pymysql", "mysql"}:
                kind, severity, message = _RESOURCE_CREATORS["connect"]
                self._add(node, label, kind, severity, message)


class ResourceLeakAnalyzer:
    """Detect potentially unclosed files, sockets, and database connections.

    Flags ``open()`` calls not used in ``with`` statements, raw socket creation,
    and database ``connect()`` calls without context managers.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[ResourceLeak] = []
        self._stats: ResourceLeakStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[ResourceLeak]:
        """Analyze the project and return resource-leak findings."""
        if self._findings:
            return self._findings

        findings: list[ResourceLeak] = []
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

        by_kind: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = ResourceLeakStats(
            total_findings=len(findings),
            by_kind=by_kind,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> ResourceLeakStats:
        """Return aggregate resource-leak statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_kind(self, kind: str) -> list[ResourceLeak]:
        """Return findings for a specific kind (e.g. file, socket, database)."""
        return [f for f in self.analyze() if f.kind == kind]

    def high_severity(self) -> list[ResourceLeak]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no resource leaks detected)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 12.0 + medium * 5.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Resource leaks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_kind:
            kinds = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_kind.items()))
            lines.append(f"By kind: {kinds}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing resource-leak findings."""
        self.analyze()
        lines = [
            "Resource leak analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No potential resource leaks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
