"""ResourceLeakAnalyzer — detect unclosed files, sockets, and connections."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

# Context managers and calls that should be closed or used with ``with``.
_RESOURCE_FACTORIES: dict[str, tuple[str, str, str]] = {
    "open": ("file", "high", "file opened without context manager — use 'with open(...) as f'"),
    "TemporaryFile": ("file", "medium", "temp file created without context manager"),
    "NamedTemporaryFile": ("file", "medium", "temp file created without context manager"),
    "socket": ("socket", "high", "socket created without context manager or explicit close()"),
    "create_connection": ("socket", "high", "connection opened without context manager or close()"),
    "connect": ("connection", "high", "connection opened without context manager or close()"),
    "SSLSocket": ("socket", "high", "SSL socket created without context manager or close()"),
    "connect_ex": ("socket", "medium", "socket connect without guaranteed close()"),
    "urlopen": ("connection", "high", "urlopen() without context manager — use 'with urlopen(...) as resp'"),
    "Popen": ("process", "medium", "subprocess.Popen without context manager or wait()/communicate()"),
}


@dataclass
class ResourceLeak:
    """A potentially unclosed resource."""

    path: str
    resource: str
    lineno: int
    kind: str
    severity: str
    message: str
    in_function: str | None = None

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.in_function}()" if self.in_function else ""
        return f"{loc}{fn} [{self.severity}] {self.kind}: {self.resource} — {self.message}"


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


def _is_with_managed(node: ast.AST, parent_map: dict[ast.AST, ast.AST]) -> bool:
    """Return True if *node* is the context expression of a ``with`` statement."""
    parent = parent_map.get(node)
    if isinstance(parent, ast.withitem):
        return parent.context_expr is node
    return False


def _has_close_in_scope(node: ast.Call, parent_map: dict[ast.AST, ast.AST]) -> bool:
    """Heuristic: variable assigned from call and .close() invoked later in same block."""
    parent = parent_map.get(node)
    if not isinstance(parent, ast.Assign) or len(parent.targets) != 1:
        return False
    target = parent.targets[0]
    if not isinstance(target, ast.Name):
        return False
    var_name = target.id

    # Walk enclosing function/module for var_name.close()
    block = parent_map.get(parent)
    while block is not None and not isinstance(block, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
        block = parent_map.get(block)

    if block is None:
        return False

    for child in ast.walk(block):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            if (
                child.func.attr == "close"
                and isinstance(child.func.value, ast.Name)
                and child.func.value.id == var_name
            ):
                return True
    return False


class _ResourceLeakVisitor(ast.NodeVisitor):
    """Walk a module AST and flag resources not managed by ``with`` or close()."""

    def __init__(self, path: str, parent_map: dict[ast.AST, ast.AST]) -> None:
        self.path = path
        self.parent_map = parent_map
        self.findings: list[ResourceLeak] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str | None:
        return self._function_stack[-1] if self._function_stack else None

    def _add(
        self,
        node: ast.Call,
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
                in_function=self._current_function(),
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
        if _is_with_managed(node, self.parent_map):
            self.generic_visit(node)
            return
        if _has_close_in_scope(node, self.parent_map):
            self.generic_visit(node)
            return

        name = _call_name(node)
        if name and name in _RESOURCE_FACTORIES:
            kind, severity, message = _RESOURCE_FACTORIES[name]
            # open() is the most common — always flag bare open() calls
            if name == "open":
                self._add(node, "open()", kind, severity, message)
            elif name == "urlopen":
                if isinstance(node.func, ast.Attribute):
                    mod = node.func.value
                    if isinstance(mod, ast.Name) and mod.id in {"urllib", "urllib.request"}:
                        self._add(node, "urlopen()", kind, severity, message)
                elif isinstance(node.func, ast.Name):
                    self._add(node, "urlopen()", kind, severity, message)
            elif name == "Popen":
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                        self._add(node, "subprocess.Popen()", kind, severity, message)
                elif isinstance(node.func, ast.Name):
                    self._add(node, "Popen()", kind, severity, message)
            elif name == "socket":
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "socket":
                        self._add(node, "socket.socket()", kind, severity, message)
            elif name in {"create_connection", "connect", "connect_ex"}:
                if isinstance(node.func, ast.Attribute):
                    mod = node.func.value
                    if isinstance(mod, ast.Name) and mod.id == "socket":
                        self._add(node, f"socket.{name}()", kind, severity, message)
            elif name in {"TemporaryFile", "NamedTemporaryFile"}:
                if isinstance(node.func, ast.Attribute):
                    mod = node.func.value
                    if isinstance(mod, ast.Name) and mod.id == "tempfile":
                        self._add(node, f"tempfile.{name}()", kind, severity, message)
            else:
                self._add(node, name, kind, severity, message)

        self.generic_visit(node)


def _build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parent_map: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[child] = node
    return parent_map


class ResourceLeakAnalyzer:
    """Detect potentially unclosed files, sockets, and connections.

    Flags ``open()`` calls not used as context managers, bare ``socket`` and
    ``subprocess.Popen`` usage, and ``urllib.urlopen`` without ``with``.
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
            parent_map = _build_parent_map(tree)
            visitor = _ResourceLeakVisitor(rel, parent_map)
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
        """Return findings for a specific resource kind (file, socket, etc.)."""
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
        penalty = high * 18.0 + medium * 7.0
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
            lines.append("No resource leaks detected.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
