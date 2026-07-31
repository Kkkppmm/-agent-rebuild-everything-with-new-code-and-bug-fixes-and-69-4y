"""ResourceLeakAnalyzer — detect unclosed files, sockets, and connections."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_CONNECT_MODULES = frozenset(
    {
        "sqlite3",
        "psycopg2",
        "psycopg",
        "pymysql",
        "mysql",
        "mysql.connector",
        "asyncpg",
        "redis",
        "aioredis",
        "aiohttp",
        "httpx",
        "urllib3",
    }
)


@dataclass
class ResourceLeak:
    """A detected resource that may not be closed."""

    path: str
    name: str
    lineno: int
    kind: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        location = f"{self.path}:{self.lineno}"
        if self.function:
            location = f"{location} ({self.function})"
        return (
            f"{location} [{self.severity}] {self.kind}: "
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


def _module_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return None


def _resource_info(node: ast.Call) -> tuple[str, str] | None:
    """Return (kind, display_name) if the call allocates a closable resource."""
    name = _call_name(node)

    if name == "open":
        if isinstance(node.func, ast.Name):
            return "file", "open"
        if isinstance(node.func, ast.Attribute):
            base = _module_name(node.func.value)
            label = f"{base}.open" if base else "open"
            return "file", label

    if name == "socket":
        if isinstance(node.func, ast.Attribute):
            base = _module_name(node.func.value)
            if base == "socket" or (base and base.endswith("socket")):
                return "socket", "socket.socket"

    if name == "connect":
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                base = node.func.value.id
                if base in _CONNECT_MODULES:
                    return "connection", f"{base}.connect"
            else:
                base = _module_name(node.func.value)
                if base and (base in _CONNECT_MODULES or base.split(".")[0] in _CONNECT_MODULES):
                    return "connection", f"{base}.connect"

    if name == "TemporaryFile":
        if isinstance(node.func, ast.Attribute):
            base = _module_name(node.func.value)
            if base and "tempfile" in base:
                return "file", "tempfile.TemporaryFile"

    return None


def _is_resource_call(node: ast.Call) -> bool:
    return _resource_info(node) is not None


class _FunctionResourceTracker(ast.NodeVisitor):
    """Track resource allocation and cleanup within one function scope."""

    def __init__(self, path: str, function: str) -> None:
        self.path = path
        self.function = function
        self.findings: list[ResourceLeak] = []
        self._with_managed: set[str] = set()
        self._assigned: dict[str, tuple[str, int, str]] = {}
        self._closed: set[str] = set()

    def _add(
        self,
        lineno: int,
        name: str,
        kind: str,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            ResourceLeak(
                path=self.path,
                name=name,
                lineno=lineno,
                kind=kind,
                severity=severity,
                message=message,
                function=self.function,
            )
        )

    def _track_assignment(self, targets: list[ast.expr], value: ast.expr, lineno: int) -> None:
        if not isinstance(value, ast.Call):
            return
        info = _resource_info(value)
        if info is None:
            return
        kind, display = info
        for target in targets:
            if isinstance(target, ast.Name):
                self._assigned[target.id] = (kind, lineno, display)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None and _is_resource_call(item.context_expr):
                if isinstance(item.optional_vars, ast.Name):
                    self._with_managed.add(item.optional_vars.id)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._track_assignment(node.targets, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            self._track_assignment([node.target], node.value, node.lineno)
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            info = _resource_info(node.value)
            if info is not None:
                kind, display = info
                self._add(
                    node.lineno,
                    display,
                    kind,
                    "high",
                    "resource created but not assigned, managed with 'with', or closed",
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr == "close":
            if isinstance(node.func.value, ast.Name):
                self._closed.add(node.func.value.id)
        self.generic_visit(node)

    def finalize(self) -> None:
        for var, (kind, lineno, display) in self._assigned.items():
            if var in self._with_managed or var in self._closed:
                continue
            self._add(
                lineno,
                display,
                kind,
                "high",
                f"'{var}' from {display}() may not be closed — use 'with' or call .close()",
            )


class _ResourceLeakVisitor(ast.NodeVisitor):
    """Walk a module AST and collect resource leaks per function."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ResourceLeak] = []

    def _scan_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        tracker = _FunctionResourceTracker(self.path, node.name)
        for child in node.body:
            tracker.visit(child)
        tracker.finalize()
        self.findings.extend(tracker.findings)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scan_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scan_function(node)
        self.generic_visit(node)

    def visit_Module(self, node: ast.Module) -> None:
        tracker = _FunctionResourceTracker(self.path, "<module>")
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            tracker.visit(child)
        tracker.finalize()
        self.findings.extend(tracker.findings)
        self.generic_visit(node)


class ResourceLeakAnalyzer:
    """Detect unclosed files, sockets, and database connections in a project.

    Flags ``open()`` calls not used with ``with`` or ``.close()``, bare
    ``socket.socket()`` allocations, and common ``*.connect()`` patterns.
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
        """Return findings for a specific kind (file, socket, connection)."""
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
        penalty = high * 18.0 + medium * 8.0
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
