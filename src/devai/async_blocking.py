"""AsyncBlockingDetector — detect blocking calls inside async functions."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

# name -> (kind, severity, message)
_BLOCKING_BUILTINS: dict[str, tuple[str, str, str]] = {
    "open": (
        "io_blocking",
        "medium",
        "open() blocks the event loop — use aiofiles or run_in_executor()",
    ),
    "input": (
        "io_blocking",
        "high",
        "input() blocks the event loop — use an async prompt or run_in_executor()",
    ),
}

_BLOCKING_ATTRS: dict[str, tuple[str, str, str]] = {
    "sleep": (
        "time_blocking",
        "high",
        "time.sleep() blocks the event loop — use asyncio.sleep()",
    ),
    "get": (
        "network_blocking",
        "medium",
        "sync HTTP call blocks the event loop — use an async HTTP client",
    ),
    "post": (
        "network_blocking",
        "medium",
        "sync HTTP call blocks the event loop — use an async HTTP client",
    ),
    "put": (
        "network_blocking",
        "medium",
        "sync HTTP call blocks the event loop — use an async HTTP client",
    ),
    "delete": (
        "network_blocking",
        "medium",
        "sync HTTP call blocks the event loop — use an async HTTP client",
    ),
    "patch": (
        "network_blocking",
        "medium",
        "sync HTTP call blocks the event loop — use an async HTTP client",
    ),
    "request": (
        "network_blocking",
        "medium",
        "sync HTTP call blocks the event loop — use an async HTTP client",
    ),
    "urlopen": (
        "network_blocking",
        "medium",
        "urllib urlopen() blocks the event loop — use an async HTTP client",
    ),
    "connect": (
        "io_blocking",
        "medium",
        "sync connect() blocks the event loop — use an async driver or run_in_executor()",
    ),
    "run": (
        "subprocess_blocking",
        "high",
        "subprocess.run() blocks the event loop — use asyncio.create_subprocess_*",
    ),
    "call": (
        "subprocess_blocking",
        "high",
        "subprocess.call() blocks the event loop — use asyncio.create_subprocess_*",
    ),
    "check_call": (
        "subprocess_blocking",
        "high",
        "subprocess.check_call() blocks the event loop — use asyncio.create_subprocess_*",
    ),
    "check_output": (
        "subprocess_blocking",
        "high",
        "subprocess.check_output() blocks the event loop — use asyncio.create_subprocess_*",
    ),
    "Popen": (
        "subprocess_blocking",
        "high",
        "subprocess.Popen() blocks the event loop — use asyncio.create_subprocess_*",
    ),
    "system": (
        "subprocess_blocking",
        "high",
        "os.system() blocks the event loop — use asyncio.create_subprocess_*",
    ),
    "popen": (
        "subprocess_blocking",
        "medium",
        "os.popen() blocks the event loop — use asyncio.create_subprocess_*",
    ),
}

_BLOCKING_MODULES = {
    "time": {"sleep"},
    "requests": {"get", "post", "put", "delete", "patch", "request", "head", "options"},
    "urllib": {"urlopen"},
    "subprocess": {"run", "call", "check_call", "check_output", "Popen"},
    "os": {"system", "popen"},
    "sqlite3": {"connect"},
    "socket": {"socket", "create_connection"},
    "httpx": {"get", "post", "put", "delete", "patch", "request", "head", "options"},
}


@dataclass
class AsyncBlockingCall:
    """A blocking call detected inside an async function."""

    path: str
    function: str
    name: str
    lineno: int
    kind: str
    severity: str
    message: str

    def format(self) -> str:
        """Return a single-line description."""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.kind}: "
            f"{self.function}() calls {self.name} — {self.message}"
        )


@dataclass
class AsyncBlockingStats:
    """Aggregate async-blocking statistics."""

    total_findings: int
    by_kind: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    async_functions_scanned: int = 0
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


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_async_safe_call(node: ast.Call) -> bool:
    """Return True when the call is known to be async-safe."""
    if isinstance(node.func, ast.Attribute):
        base = node.func.value
        if isinstance(base, ast.Name) and base.id == "asyncio":
            return True
        if isinstance(base, ast.Name) and base.id in {"aiohttp", "aiofiles"}:
            return True
        if isinstance(base, ast.Attribute):
            module = _module_name(base)
            if module and module.split(".")[0] in {"asyncio", "aiohttp", "aiofiles"}:
                return True
    return False


def _blocking_from_call(node: ast.Call) -> tuple[str, str, str, str] | None:
    """Return (display_name, kind, severity, message) if the call is blocking."""
    if _is_async_safe_call(node):
        return None

    name = _call_name(node)
    if name is None:
        return None

    if isinstance(node.func, ast.Name) and name in _BLOCKING_BUILTINS:
        kind, severity, message = _BLOCKING_BUILTINS[name]
        return name, kind, severity, message

    if not isinstance(node.func, ast.Attribute):
        return None

    base = node.func.value
    if isinstance(base, ast.Name):
        module = base.id
        if module in _BLOCKING_MODULES and name in _BLOCKING_MODULES[module]:
            if name in _BLOCKING_ATTRS:
                kind, severity, message = _BLOCKING_ATTRS[name]
            else:
                kind, severity, message = (
                    "io_blocking",
                    "medium",
                    f"{module}.{name}() blocks the event loop — use an async alternative",
                )
            return f"{module}.{name}", kind, severity, message

    if name in _BLOCKING_ATTRS:
        kind, severity, message = _BLOCKING_ATTRS[name]
        if name == "sleep" and isinstance(base, ast.Name) and base.id == "time":
            return "time.sleep", kind, severity, message
        if name in {"run", "call", "check_call", "check_output", "Popen"}:
            if isinstance(base, ast.Name) and base.id == "subprocess":
                return f"subprocess.{name}", kind, severity, message
        if name in {"system", "popen"}:
            if isinstance(base, ast.Name) and base.id == "os":
                return f"os.{name}", kind, severity, message

    return None


class _AsyncBlockingVisitor(ast.NodeVisitor):
    """Walk a module AST and collect blocking calls inside async functions."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[AsyncBlockingCall] = []
        self._async_depth = 0
        self._current_function = ""

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        prev = self._current_function
        self._current_function = node.name
        self._async_depth += 1
        self.generic_visit(node)
        self._async_depth -= 1
        self._current_function = prev

    def visit_Call(self, node: ast.Call) -> None:
        if self._async_depth > 0:
            result = _blocking_from_call(node)
            if result:
                display_name, kind, severity, message = result
                lineno = getattr(node, "lineno", 1)
                self.findings.append(
                    AsyncBlockingCall(
                        path=self.path,
                        function=self._current_function,
                        name=display_name,
                        lineno=lineno,
                        kind=kind,
                        severity=severity,
                        message=message,
                    )
                )
        self.generic_visit(node)


class AsyncBlockingDetector:
    """Detect blocking calls inside ``async def`` functions.

    Flags ``time.sleep``, sync HTTP clients (``requests``, ``httpx``),
    ``open()``, ``subprocess`` calls, ``os.system``, ``input()``,
    and other operations that block the asyncio event loop.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[AsyncBlockingCall] = []
        self._stats: AsyncBlockingStats | None = None
        self._files_scanned = 0
        self._async_functions = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[AsyncBlockingCall]:
        """Analyze the project and return async-blocking findings."""
        if self._findings:
            return self._findings

        findings: list[AsyncBlockingCall] = []
        files_scanned = 0
        async_functions = 0
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
            visitor = _AsyncBlockingVisitor(rel)
            visitor.visit(tree)
            async_functions += sum(
                1 for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef)
            )
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned
        self._async_functions = async_functions

        by_kind: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if async_functions:
            density = round(100.0 * len(findings) / async_functions, 1)

        self._stats = AsyncBlockingStats(
            total_findings=len(findings),
            by_kind=by_kind,
            by_severity=by_severity,
            async_functions_scanned=async_functions,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> AsyncBlockingStats:
        """Return aggregate async-blocking statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_kind(self, kind: str) -> list[AsyncBlockingCall]:
        """Return findings for a specific kind (e.g. time_blocking, network_blocking)."""
        return [f for f in self.analyze() if f.kind == kind]

    def high_severity(self) -> list[AsyncBlockingCall]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no blocking calls in async functions)."""
        self.analyze()
        if self._async_functions == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        ratio = penalty / self._async_functions
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Async blocking: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._async_functions} async functions scanned)",
            f"Density: {stats.finding_density} findings per 100 async functions",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_kind:
            kinds = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_kind.items()))
            lines.append(f"By kind: {kinds}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing async-blocking findings."""
        self.analyze()
        lines = [
            "Async blocking analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No blocking calls found in async functions.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
