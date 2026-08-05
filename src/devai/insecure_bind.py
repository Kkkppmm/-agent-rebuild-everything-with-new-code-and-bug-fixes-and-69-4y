"""InsecureBindAnalyzer — detect services bound to all network interfaces."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_INSECURE_HOSTS = frozenset({"0.0.0.0", "::", "", "0"})
_BIND_HOST_KWARGS = frozenset({"host", "bind", "bind_address", "listen_address"})
_SERVER_CALLS = frozenset(
    {
        "run",
        "serve",
        "listen",
        "create_server",
        "start_server",
    }
)
_SERVER_MODULES = frozenset(
    {
        "app",
        "uvicorn",
        "hypercorn",
        "waitress",
        "socketio",
        "flask",
    }
)
_SERVER_CLASSES = frozenset(
    {
        "HTTPServer",
        "TCPServer",
        "ThreadingHTTPServer",
        "ThreadingTCPServer",
        "SimpleHTTPRequestHandler",
        "WSGIServer",
        "make_server",
    }
)


@dataclass
class InsecureBindFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    host: str = ""
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        host = f" ({self.host})" if self.host else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}{host}: {self.message}"


@dataclass
class InsecureBindStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_label(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        base = ""
        if isinstance(func.value, ast.Name):
            base = func.value.id
        elif isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            base = f"{func.value.value.id}.{func.value.attr}"
        return f"{base}.{func.attr}" if base else func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_insecure_host(value: str) -> bool:
    return value in _INSECURE_HOSTS


def _tuple_host(node: ast.AST) -> str | None:
    if isinstance(node, ast.Tuple) and node.elts:
        return _string_value(node.elts[0])
    return _string_value(node)


class _InsecureBindVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureBindFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add_finding(
        self,
        node: ast.AST,
        *,
        pattern: str,
        host: str,
        message: str,
        severity: str = "high",
    ) -> None:
        self.findings.append(
            InsecureBindFinding(
                path=self.path,
                lineno=node.lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                host=host,
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

    def _check_host_kwarg(self, node: ast.Call, host: str) -> None:
        if _is_insecure_host(host):
            self._add_finding(
                node,
                pattern="insecure_bind_host",
                host=host or '""',
                message=(
                    f"Binding to {host or 'all interfaces'} exposes the service on every "
                    "network interface — use 127.0.0.1 for local-only or a specific IP"
                ),
            )

    def _check_bind_call(self, node: ast.Call) -> None:
        label = _call_label(node)
        if label.endswith(".bind") and node.args:
            host = _tuple_host(node.args[0])
            if host is not None and _is_insecure_host(host):
                self._add_finding(
                    node,
                    pattern="socket_bind_all_interfaces",
                    host=host or '""',
                    message="socket.bind() on all interfaces — restrict to 127.0.0.1 unless intentionally public",
                )

        for kw in node.keywords:
            if kw.arg in _BIND_HOST_KWARGS:
                host = _string_value(kw.value)
                if host is not None:
                    self._check_host_kwarg(node, host)

        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _SERVER_CALLS:
            module = ""
            if isinstance(func.value, ast.Name):
                module = func.value.id
            if module in _SERVER_MODULES or func.attr == "run":
                for kw in node.keywords:
                    if kw.arg == "host":
                        host = _string_value(kw.value)
                        if host is not None:
                            self._check_host_kwarg(node, host)

        if isinstance(func, ast.Name) and func.id in _SERVER_CLASSES and node.args:
            host = _tuple_host(node.args[0])
            if host is not None and _is_insecure_host(host):
                self._add_finding(
                    node,
                    pattern="server_all_interfaces",
                    host=host or '""',
                    message="HTTP server listening on all interfaces — bind to 127.0.0.1 for development",
                )

        if isinstance(func, ast.Attribute) and func.attr in _SERVER_CLASSES and node.args:
            host = _tuple_host(node.args[0])
            if host is not None and _is_insecure_host(host):
                self._add_finding(
                    node,
                    pattern="server_all_interfaces",
                    host=host or '""',
                    message="HTTP server listening on all interfaces — bind to 127.0.0.1 for development",
                )

    def visit_Call(self, node: ast.Call) -> None:
        self._check_bind_call(node)
        self.generic_visit(node)


class InsecureBindAnalyzer:
    """Detect services bound to 0.0.0.0 or all network interfaces."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureBindFinding] = []
        self._stats: InsecureBindStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[InsecureBindFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureBindFinding] = []
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
            visitor = _InsecureBindVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = InsecureBindStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureBindStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 30.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure bind: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure bind analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure bind addresses found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
