"""AsyncBlockingDetector — detect blocking calls inside async functions."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_BLOCKING_CALLS: dict[str, tuple[str, str, str]] = {
    "sleep": ("time", "high", "time.sleep() blocks the event loop — use asyncio.sleep()"),
    "get": ("http", "high", "synchronous HTTP call blocks the event loop — use httpx/aiohttp async clients"),
    "post": ("http", "high", "synchronous HTTP call blocks the event loop — use httpx/aiohttp async clients"),
    "put": ("http", "high", "synchronous HTTP call blocks the event loop — use httpx/aiohttp async clients"),
    "delete": ("http", "high", "synchronous HTTP call blocks the event loop — use httpx/aiohttp async clients"),
    "request": ("http", "high", "synchronous HTTP call blocks the event loop — use httpx/aiohttp async clients"),
    "urlopen": ("http", "high", "urllib blocks the event loop — use an async HTTP client"),
    "read": ("io", "medium", "synchronous read() may block — use async file I/O or run_in_executor"),
    "write": ("io", "medium", "synchronous write() may block — use async file I/O or run_in_executor"),
    "run": ("subprocess", "high", "subprocess.run() blocks the event loop — use asyncio.create_subprocess_exec"),
    "call": ("subprocess", "high", "subprocess.call() blocks the event loop — use asyncio.create_subprocess_exec"),
    "Popen": ("subprocess", "high", "subprocess.Popen() blocks the event loop — use asyncio.create_subprocess_exec"),
    "connect": ("network", "high", "synchronous connect() blocks the event loop — use an async client"),
    "recv": ("network", "high", "synchronous recv() blocks the event loop — use asyncio streams"),
    "send": ("network", "medium", "synchronous send() may block — use asyncio streams"),
    "acquire": ("threading", "high", "threading lock acquire blocks the event loop — use asyncio.Lock"),
    "join": ("threading", "high", "thread.join() blocks the event loop — use asyncio tasks"),
}


@dataclass
class AsyncBlockingFinding:
    """A blocking call detected inside an async function."""

    path: str
    function: str
    call: str
    lineno: int
    kind: str
    severity: str
    message: str

    def format(self) -> str:
        """Return a single-line description."""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.kind}: "
            f"{self.function}() calls {self.call} — {self.message}"
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


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _call_context(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        return func.attr
    return "unknown"


def _is_requests_call(node: ast.Call, name: str | None) -> bool:
    if name not in {"get", "post", "put", "delete", "request"}:
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id in {"requests", "httpx"}
    return False


def _is_time_sleep(node: ast.Call, name: str | None) -> bool:
    if name != "sleep":
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id == "time"
    return name == "sleep"


def _is_subprocess_call(node: ast.Call, name: str | None) -> bool:
    if name not in {"run", "call", "Popen", "check_output", "check_call"}:
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id == "subprocess"
    return False


def _is_blocking_open(node: ast.Call, name: str | None) -> bool:
    return name == "open"


class _AsyncBlockingVisitor(ast.NodeVisitor):
    """Walk async functions and flag blocking calls."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[AsyncBlockingFinding] = []
        self.async_functions_scanned = 0
        self._async_stack: list[str] = []

    def _add(
        self,
        node: ast.AST,
        call: str,
        kind: str,
        severity: str,
        message: str,
    ) -> None:
        if not self._async_stack:
            return
        lineno = getattr(node, "lineno", 1)
        self.findings.append(
            AsyncBlockingFinding(
                path=self.path,
                function=self._async_stack[-1],
                call=call,
                lineno=lineno,
                kind=kind,
                severity=severity,
                message=message,
            )
        )

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._async_stack.append(node.name)
        self.async_functions_scanned += 1
        self.generic_visit(node)
        self._async_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if not self._async_stack:
            self.generic_visit(node)
            return

        name = _call_name(node)
        call_label = _call_context(node)

        if _is_time_sleep(node, name):
            kind, severity, message = _BLOCKING_CALLS["sleep"]
            self._add(node, call_label, kind, severity, message)
        elif _is_requests_call(node, name):
            kind, severity, message = _BLOCKING_CALLS.get(name, ("http", "high", "blocking HTTP call"))
            self._add(node, call_label, kind, severity, message)
        elif _is_subprocess_call(node, name):
            kind, severity, message = _BLOCKING_CALLS["run"]
            self._add(node, call_label, kind, severity, message)
        elif _is_blocking_open(node, name):
            self._add(
                node,
                call_label,
                "io",
                "medium",
                "open() without async I/O may block the event loop — use aiofiles or run_in_executor",
            )
        elif name and name in _BLOCKING_CALLS and name != "sleep":
            kind, severity, message = _BLOCKING_CALLS[name]
            self._add(node, call_label, kind, severity, message)

        self.generic_visit(node)


class AsyncBlockingDetector:
    """Detect blocking calls inside ``async def`` functions.

    Flags synchronous I/O, ``time.sleep``, blocking HTTP clients,
    subprocess calls, and threading primitives that can stall the event loop.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[AsyncBlockingFinding] = []
        self._stats: AsyncBlockingStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[AsyncBlockingFinding]:
        """Analyze the project and return async-blocking findings."""
        if self._findings:
            return self._findings

        findings: list[AsyncBlockingFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()
        async_functions = 0

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
            async_functions += visitor.async_functions_scanned
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

    def by_kind(self, kind: str) -> list[AsyncBlockingFinding]:
        """Return findings for a specific kind (e.g. http, subprocess)."""
        return [f for f in self.analyze() if f.kind == kind]

    def high_severity(self) -> list[AsyncBlockingFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no blocking calls in async code)."""
        self.analyze()
        stats = self.stats
        if stats.async_functions_scanned == 0:
            return 100.0
        high = stats.by_severity.get("high", 0)
        medium = stats.by_severity.get("medium", 0)
        penalty = high * 15.0 + medium * 6.0
        ratio = penalty / stats.async_functions_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Async blocking: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Async functions scanned: {stats.async_functions_scanned}",
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
