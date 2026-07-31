"""ResourceLeakAnalyzer — detect unclosed files, sockets, and connections."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_RESOURCE_CALLS: dict[str, tuple[str, str, str]] = {
    "open": ("unclosed_file", "medium", "open() without a context manager may leak file handles"),
    "connect": ("unclosed_connection", "high", "connect() without a context manager may leak connections"),
    "socket": ("unclosed_socket", "medium", "socket() without a context manager may leak sockets"),
    "urlopen": ("unclosed_connection", "medium", "urlopen() without a context manager may leak connections"),
}


@dataclass
class ResourceLeak:
    """A detected resource that may not be closed properly."""

    path: str
    name: str
    lineno: int
    kind: str
    severity: str
    message: str

    def format(self) -> str:
        """Return a single-line description."""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.kind}: "
            f"{self.name} — {self.message}"
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


def _is_sqlite_connect(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr != "connect":
        return False
    value = node.func.value
    if isinstance(value, ast.Name) and value.id == "sqlite3":
        return True
    if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
        return value.value.id == "sqlite3"
    return False


def _is_socket_call(node: ast.Call) -> bool:
    name = _call_name(node)
    if name != "socket":
        return False
    if isinstance(node.func, ast.Attribute):
        value = node.func.value
        return isinstance(value, ast.Name) and value.id == "socket"
    return isinstance(node.func, ast.Name)


def _is_urlopen_call(node: ast.Call) -> bool:
    name = _call_name(node)
    if name != "urlopen":
        return False
    if isinstance(node.func, ast.Attribute):
        value = node.func.value
        if isinstance(value, ast.Name) and value.id in {"urllib", "request"}:
            return True
        if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            return value.value.id == "urllib" and value.attr == "request"
    return isinstance(node.func, ast.Name)


def _is_resource_call(node: ast.Call) -> bool:
    name = _call_name(node)
    if name == "open":
        return True
    if _is_sqlite_connect(node):
        return True
    if _is_socket_call(node):
        return True
    if _is_urlopen_call(node):
        return True
    return name == "connect" and isinstance(node.func, ast.Attribute)


class _ResourceLeakVisitor(ast.NodeVisitor):
    """Walk a module AST and collect potentially unclosed resources."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ResourceLeak] = []
        self._with_context_ids: set[int] = set()
        self._closed_names: set[str] = set()
        self._resource_assignments: dict[str, ast.Call] = {}
        self._function_stack: list[str] = []

    def _qualified_name(self, name: str) -> str:
        if self._function_stack:
            return f"{self._function_stack[-1]}.{name}"
        return name

    def _add(
        self,
        node: ast.AST,
        name: str,
        kind: str,
        severity: str,
        message: str,
    ) -> None:
        lineno = getattr(node, "lineno", 1)
        self.findings.append(
            ResourceLeak(
                path=self.path,
                name=name,
                lineno=lineno,
                kind=kind,
                severity=severity,
                message=message,
            )
        )

    def _record_with_context(self, node: ast.With) -> None:
        for item in node.items:
            self._with_context_ids.add(id(item.context_expr))

    def _is_managed_resource(self, node: ast.Call) -> bool:
        return id(node) in self._with_context_ids

    def _check_resource_call(self, node: ast.Call) -> None:
        if self._is_managed_resource(node) or not _is_resource_call(node):
            return

        name = _call_name(node)
        if name == "open":
            kind, severity, message = _RESOURCE_CALLS["open"]
            self._add(node, "open", kind, severity, message)
            return

        if _is_sqlite_connect(node):
            kind, severity, message = _RESOURCE_CALLS["connect"]
            self._add(node, "sqlite3.connect", kind, severity, message)
            return

        if _is_socket_call(node):
            kind, severity, message = _RESOURCE_CALLS["socket"]
            self._add(node, "socket.socket", kind, severity, message)
            return

        if _is_urlopen_call(node):
            kind, severity, message = _RESOURCE_CALLS["urlopen"]
            self._add(node, "urlopen", kind, severity, message)
            return

        if name == "connect" and isinstance(node.func, ast.Attribute):
            kind, severity, message = _RESOURCE_CALLS["connect"]
            module = ""
            if isinstance(node.func.value, ast.Name):
                module = f"{node.func.value.id}."
            self._add(node, f"{module}connect", kind, severity, message)

    def visit_With(self, node: ast.With) -> None:
        self._record_with_context(node)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._record_with_context(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if (
            isinstance(node.value, ast.Call)
            and not self._is_managed_resource(node.value)
            and _is_resource_call(node.value)
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._resource_assignments[target.id] = node.value
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Attribute) and func.attr == "close":
                if isinstance(func.value, ast.Name):
                    self._closed_names.add(func.value.id)
            else:
                self._check_resource_call(node.value)
        self.generic_visit(node)

    def _severity_for_call(self, call_node: ast.Call) -> str:
        if _is_sqlite_connect(call_node):
            return "high"
        if _is_socket_call(call_node) or _is_urlopen_call(call_node):
            return "medium"
        name = _call_name(call_node)
        if name == "open":
            return "medium"
        if name == "connect":
            return "high"
        return "medium"

    def _finalize_function(self) -> None:
        for var_name, call_node in self._resource_assignments.items():
            if var_name in self._closed_names or self._is_managed_resource(call_node):
                continue
            self._add(
                call_node,
                self._qualified_name(var_name),
                "unclosed_assignment",
                self._severity_for_call(call_node),
                f"assigned resource '{var_name}' is never closed — use a context manager",
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        saved_assignments = self._resource_assignments.copy()
        saved_closed = self._closed_names.copy()
        self._resource_assignments = {}
        self._closed_names = set()
        self.generic_visit(node)
        self._finalize_function()
        self._resource_assignments = saved_assignments
        self._closed_names = saved_closed
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        saved_assignments = self._resource_assignments.copy()
        saved_closed = self._closed_names.copy()
        self._resource_assignments = {}
        self._closed_names = set()
        self.generic_visit(node)
        self._finalize_function()
        self._resource_assignments = saved_assignments
        self._closed_names = saved_closed
        self._function_stack.pop()


class ResourceLeakAnalyzer:
    """Detect potentially unclosed files, sockets, and database connections.

    Flags ``open()`` without ``with``, ``sqlite3.connect()`` without cleanup,
    ``socket.socket()`` leaks, and assigned resources that are never closed.
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
        """Return findings for a specific kind (e.g. unclosed_file)."""
        return [f for f in self.analyze() if f.kind == kind]

    def high_severity(self) -> list[ResourceLeak]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no resource leaks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 15.0 + medium * 6.0
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
            lines.append("No resource leaks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
