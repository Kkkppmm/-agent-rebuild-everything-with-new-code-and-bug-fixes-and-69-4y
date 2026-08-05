"""MissingTimeoutAnalyzer — detect network and subprocess calls without timeouts."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_REQUESTS_METHODS = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "request",
    }
)
_HTTPX_METHODS = _REQUESTS_METHODS
_SUBPROCESS_FUNCS = frozenset({"run", "call", "check_call", "check_output", "Popen", "communicate"})
_URLLIB_FUNCS = frozenset({"urlopen", "urlretrieve"})
_SOCKET_FUNCS = frozenset({"create_connection", "connect"})


@dataclass
class MissingTimeoutFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    call: str = ""
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        call = f" ({self.call})" if self.call else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}{call}: {self.message}"


@dataclass
class MissingTimeoutStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_attr(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _call_module(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return None


def _has_timeout_kwarg(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "timeout":
            return True
    return False


def _is_requests_call(node: ast.Call) -> str | None:
    attr = _call_attr(node)
    if attr not in _REQUESTS_METHODS:
        return None
    module = _call_module(node)
    if module == "requests":
        return f"requests.{attr}"
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Attribute):
        base = node.func.value
        if isinstance(base.value, ast.Name) and base.value.id == "requests" and base.attr == "Session":
            return f"requests.Session().{attr}"
    return None


def _is_httpx_call(node: ast.Call) -> str | None:
    attr = _call_attr(node)
    if attr not in _HTTPX_METHODS:
        return None
    module = _call_module(node)
    if module == "httpx":
        return f"httpx.{attr}"
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Attribute):
        base = node.func.value
        if isinstance(base.value, ast.Name) and base.value.id == "httpx" and base.attr in {"Client", "AsyncClient"}:
            return f"httpx.{base.attr}().{attr}"
    return None


def _is_urllib_call(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        if func.attr in _URLLIB_FUNCS:
            if isinstance(func.value, ast.Attribute) and func.value.attr == "request":
                if isinstance(func.value.value, ast.Name) and func.value.value.id == "urllib":
                    return f"urllib.request.{func.attr}"
            if isinstance(func.value, ast.Name) and func.value.id == "urlopen":
                return "urlopen"
    if isinstance(func, ast.Name) and func.id == "urlopen":
        return "urlopen"
    return None


def _is_subprocess_call(node: ast.Call) -> str | None:
    attr = _call_attr(node)
    if attr not in _SUBPROCESS_FUNCS:
        return None
    module = _call_module(node)
    if module == "subprocess":
        return f"subprocess.{attr}"
    return None


def _is_socket_call(node: ast.Call) -> str | None:
    attr = _call_attr(node)
    if attr not in _SOCKET_FUNCS:
        return None
    module = _call_module(node)
    if module == "socket":
        return f"socket.{attr}"
    return None


class _MissingTimeoutVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[MissingTimeoutFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.Call,
        *,
        pattern: str,
        severity: str,
        message: str,
        call: str,
    ) -> None:
        self.findings.append(
            MissingTimeoutFinding(
                path=self.path,
                lineno=node.lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                call=call,
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

    def visit_Call(self, node: ast.Call) -> None:
        if _has_timeout_kwarg(node):
            self.generic_visit(node)
            return

        if call := _is_requests_call(node):
            self._add(
                node,
                pattern="missing_http_timeout",
                severity="medium",
                message="HTTP request without timeout can hang indefinitely — pass timeout=<seconds>",
                call=call,
            )
        elif call := _is_httpx_call(node):
            self._add(
                node,
                pattern="missing_http_timeout",
                severity="medium",
                message="HTTP request without timeout can hang indefinitely — pass timeout=<seconds>",
                call=call,
            )
        elif call := _is_urllib_call(node):
            self._add(
                node,
                pattern="missing_http_timeout",
                severity="medium",
                message="urllib call without timeout can hang indefinitely — pass timeout=<seconds>",
                call=call,
            )
        elif call := _is_subprocess_call(node):
            self._add(
                node,
                pattern="missing_subprocess_timeout",
                severity="high",
                message="subprocess call without timeout can hang indefinitely — pass timeout=<seconds>",
                call=call,
            )
        elif call := _is_socket_call(node):
            self._add(
                node,
                pattern="missing_socket_timeout",
                severity="medium",
                message="socket call without timeout can block indefinitely — set socket timeout or use create_connection(..., timeout=)",
                call=call,
            )

        self.generic_visit(node)


class MissingTimeoutAnalyzer:
    """Detect HTTP, socket, and subprocess calls missing timeout parameters."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[MissingTimeoutFinding] = []
        self._stats: MissingTimeoutStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[MissingTimeoutFinding]:
        findings: list[MissingTimeoutFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            return findings

        visitor = _MissingTimeoutVisitor(rel)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return findings

    def analyze(self) -> list[MissingTimeoutFinding]:
        if self._findings:
            return self._findings

        findings: list[MissingTimeoutFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            file_findings = self._scan_source(rel, source)
            if file_findings:
                files_with_findings.add(rel)
            findings.extend(file_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = MissingTimeoutStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> MissingTimeoutStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Missing timeouts: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Missing timeout analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No calls missing timeouts found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
