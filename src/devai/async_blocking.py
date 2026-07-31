"""AsyncBlockingDetector — find blocking calls inside async functions."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

# Calls that block the event loop when used inside async functions.
_BLOCKING_CALLS: dict[str, tuple[str, str, str]] = {
    "sleep": ("time.sleep", "blocking_io", "medium", "time.sleep() blocks the event loop — use asyncio.sleep()"),
    "read": ("file.read", "blocking_io", "medium", "synchronous file read blocks the event loop"),
    "write": ("file.write", "blocking_io", "medium", "synchronous file write blocks the event loop"),
    "readlines": ("file.readlines", "blocking_io", "medium", "synchronous file read blocks the event loop"),
    "readline": ("file.readline", "blocking_io", "medium", "synchronous file read blocks the event loop"),
    "connect": ("socket.connect", "blocking_io", "high", "blocking connect — use asyncio streams or run_in_executor"),
    "recv": ("socket.recv", "blocking_io", "high", "blocking socket recv — use asyncio streams"),
    "send": ("socket.send", "blocking_io", "high", "blocking socket send — use asyncio streams"),
    "recvfrom": ("socket.recvfrom", "blocking_io", "high", "blocking socket recvfrom — use asyncio streams"),
    "sendall": ("socket.sendall", "blocking_io", "high", "blocking socket sendall — use asyncio streams"),
    "get": ("requests.get", "blocking_io", "high", "synchronous HTTP request blocks the event loop — use httpx.AsyncClient"),
    "post": ("requests.post", "blocking_io", "high", "synchronous HTTP request blocks the event loop — use httpx.AsyncClient"),
    "put": ("requests.put", "blocking_io", "high", "synchronous HTTP request blocks the event loop — use httpx.AsyncClient"),
    "delete": ("requests.delete", "blocking_io", "high", "synchronous HTTP request blocks the event loop — use httpx.AsyncClient"),
    "request": ("requests.request", "blocking_io", "high", "synchronous HTTP request blocks the event loop — use httpx.AsyncClient"),
    "urlopen": ("urllib.urlopen", "blocking_io", "high", "urllib blocks the event loop — use aiohttp or httpx.AsyncClient"),
    "run": ("subprocess.run", "blocking_io", "high", "subprocess.run() blocks the event loop — use asyncio.create_subprocess_exec"),
    "call": ("subprocess.call", "blocking_io", "high", "subprocess.call() blocks the event loop — use asyncio.create_subprocess_exec"),
    "check_output": ("subprocess.check_output", "blocking_io", "high", "subprocess.check_output() blocks the event loop"),
    "Popen": ("subprocess.Popen", "blocking_io", "medium", "subprocess.Popen() may block — prefer asyncio subprocess APIs"),
    "execute": ("db.execute", "blocking_io", "medium", "synchronous DB execute may block — use async driver or run_in_executor"),
    "fetchone": ("db.fetchone", "blocking_io", "medium", "synchronous DB fetch blocks the event loop"),
    "fetchall": ("db.fetchall", "blocking_io", "medium", "synchronous DB fetch blocks the event loop"),
    "commit": ("db.commit", "blocking_io", "medium", "synchronous DB commit blocks the event loop"),
}


@dataclass
class BlockingCall:
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
class BlockingCallStats:
    """Aggregate blocking-call statistics."""

    total_findings: int
    by_kind: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_label(node: ast.Call) -> tuple[str, str] | None:
    """Return (short_name, qualified_label) for a call node."""
    func = node.func
    if isinstance(func, ast.Name):
        name = func.id
        return name, name
    if isinstance(func, ast.Attribute):
        attr = func.attr
        if isinstance(func.value, ast.Name):
            module = func.value.id
            return attr, f"{module}.{attr}"
        if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            return attr, f"{func.value.value.id}.{func.value.attr}.{attr}"
        return attr, attr
    return None


class _AsyncBlockingVisitor(ast.NodeVisitor):
    """Walk async functions and flag blocking calls."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[BlockingCall] = []
        self._async_depth = 0
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else "<module>"

    def _add(self, node: ast.Call, call: str, kind: str, severity: str, message: str) -> None:
        lineno = getattr(node, "lineno", 1)
        self.findings.append(
            BlockingCall(
                path=self.path,
                function=self._current_function(),
                call=call,
                lineno=lineno,
                kind=kind,
                severity=severity,
                message=message,
            )
        )

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self._async_depth += 1
        self.generic_visit(node)
        self._async_depth -= 1
        self._function_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if self._async_depth > 0:
            label = _call_label(node)
            if label:
                short, qualified = label
                if short in _BLOCKING_CALLS:
                    _, kind, severity, message = _BLOCKING_CALLS[short]
                    # requests.* and urllib.* need module context
                    if short in {"get", "post", "put", "delete", "request"}:
                        if not qualified.startswith("requests."):
                            self.generic_visit(node)
                            return
                    if short == "urlopen" and not qualified.startswith("urllib"):
                        self.generic_visit(node)
                        return
                    if short in {"connect", "recv", "send", "recvfrom", "sendall"}:
                        if not qualified.startswith("socket."):
                            self.generic_visit(node)
                            return
                    if short in {"run", "call", "check_output", "Popen"}:
                        if not qualified.startswith("subprocess."):
                            self.generic_visit(node)
                            return
                    if short == "sleep":
                        if not qualified.startswith("time."):
                            self.generic_visit(node)
                            return
                    self._add(node, qualified, kind, severity, message)
        self.generic_visit(node)


class AsyncBlockingDetector:
    """Detect blocking calls inside ``async def`` functions.

    Flags synchronous I/O, ``time.sleep``, blocking sockets, ``requests``,
    ``subprocess``, and other calls that can stall an asyncio event loop.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[BlockingCall] = []
        self._stats: BlockingCallStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[BlockingCall]:
        """Analyze the project and return blocking-call findings."""
        if self._findings:
            return self._findings

        findings: list[BlockingCall] = []
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
            visitor = _AsyncBlockingVisitor(rel)
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

        self._stats = BlockingCallStats(
            total_findings=len(findings),
            by_kind=by_kind,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> BlockingCallStats:
        """Return aggregate blocking-call statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_kind(self, kind: str) -> list[BlockingCall]:
        """Return findings for a specific kind."""
        return [f for f in self.analyze() if f.kind == kind]

    def high_severity(self) -> list[BlockingCall]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no blocking calls in async code)."""
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
            f"Async blocking calls: {stats.total_findings} findings in "
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
        """Build LLM-ready context describing async blocking findings."""
        self.analyze()
        lines = [
            "Async blocking call analysis:",
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
