"""AsyncBlockingDetector — detect blocking calls inside async functions."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_BLOCKING_CALLS: dict[str, tuple[str, str, str]] = {
    "sleep": ("time.sleep", "high", "time.sleep() blocks the event loop — use asyncio.sleep()"),
    "get": ("requests.get", "high", "sync HTTP call blocks the event loop — use httpx/aiohttp"),
    "post": ("requests.post", "high", "sync HTTP call blocks the event loop — use httpx/aiohttp"),
    "put": ("requests.put", "high", "sync HTTP call blocks the event loop — use httpx/aiohttp"),
    "delete": ("requests.delete", "high", "sync HTTP call blocks the event loop — use httpx/aiohttp"),
    "request": ("requests.request", "high", "sync HTTP call blocks the event loop — use httpx/aiohttp"),
    "run": ("subprocess.run", "medium", "subprocess.run() blocks — use asyncio.create_subprocess_exec"),
    "call": ("subprocess.call", "medium", "subprocess.call() blocks — use asyncio.create_subprocess_exec"),
    "Popen": ("subprocess.Popen", "medium", "subprocess.Popen() in async code — prefer asyncio subprocess"),
}


@dataclass
class AsyncBlockingFinding:
    """A blocking call detected inside an async function."""

    path: str
    lineno: int
    call: str
    severity: str
    message: str
    async_function: str

    def format(self) -> str:
        """Return a single-line description."""
        return (
            f"{self.path}:{self.lineno} in async {self.async_function} "
            f"[{self.severity}] {self.call}: {self.message}"
        )


@dataclass
class AsyncBlockingStats:
    """Aggregate async-blocking statistics."""

    total_findings: int
    by_call: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    async_functions_scanned: int = 0
    files_with_findings: int = 0


def _call_label(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        attr = func.attr
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{attr}"
        return attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _is_blocking_call(node: ast.Call) -> tuple[str, str, str] | None:
    label = _call_label(node)
    if not label:
        return None

    if label == "time.sleep":
        return _BLOCKING_CALLS["sleep"]
    if label.startswith("requests."):
        attr = label.split(".", 1)[1]
        if attr in _BLOCKING_CALLS:
            return _BLOCKING_CALLS[attr]
    if label.startswith("subprocess."):
        attr = label.split(".", 1)[1]
        if attr in _BLOCKING_CALLS:
            return _BLOCKING_CALLS[attr]

    if isinstance(node.func, ast.Name) and node.func.id == "open":
        return (
            "open",
            "medium",
            "sync file open() in async function — use aiofiles or run_in_executor",
        )
    return None


class _AsyncBlockingVisitor(ast.NodeVisitor):
    """Walk async functions and collect blocking calls."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[AsyncBlockingFinding] = []
        self.async_functions_scanned = 0

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.async_functions_scanned += 1
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                result = _is_blocking_call(child)
                if result:
                    call, severity, message = result
                    self.findings.append(
                        AsyncBlockingFinding(
                            path=self.path,
                            lineno=child.lineno,
                            call=call,
                            severity=severity,
                            message=message,
                            async_function=node.name,
                        )
                    )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Do not descend into sync functions
        return


class AsyncBlockingDetector:
    """Detect blocking calls inside ``async def`` functions.

    Flags ``time.sleep``, synchronous ``requests`` calls, ``subprocess``,
    and ``open()`` used inside async coroutines.
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
        async_functions_scanned = 0

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
            async_functions_scanned += visitor.async_functions_scanned
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_call: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_call[finding.call] = by_call.get(finding.call, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        self._stats = AsyncBlockingStats(
            total_findings=len(findings),
            by_call=by_call,
            by_severity=by_severity,
            async_functions_scanned=async_functions_scanned,
            files_with_findings=len(files_with_findings),
        )
        return findings

    @property
    def stats(self) -> AsyncBlockingStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[AsyncBlockingFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no blocking calls in async code)."""
        self.analyze()
        if self._stats is None or self._stats.async_functions_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 8.0
        ratio = penalty / self._stats.async_functions_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Async blocking: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned, "
            f"{stats.async_functions_scanned} async functions)",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_call:
            calls = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_call.items()))
            lines.append(f"By call: {calls}")
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
            lines.append("No blocking calls in async functions.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
