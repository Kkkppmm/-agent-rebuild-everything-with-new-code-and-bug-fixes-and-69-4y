"""InsecureBindAnalyzer — detect services bound to all network interfaces."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_ALL_INTERFACE_HOSTS = frozenset({"0.0.0.0", "::", "", "*"})

_BIND_METHODS = frozenset({"bind", "listen"})
_SERVER_CALLS = frozenset(
    {
        "run",
        "serve",
        "serve_forever",
        "create_server",
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
        host = f" ({self.host!r})" if self.host else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}{host}: {self.message}"


@dataclass
class InsecureBindStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _host_from_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _host_from_address_tuple(node: ast.AST) -> str | None:
    if isinstance(node, ast.Tuple | ast.List) and node.elts:
        return _host_from_constant(node.elts[0])
    return None


def _is_insecure_host(host: str | None) -> bool:
    return host in _ALL_INTERFACE_HOSTS


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
        severity: str,
        message: str,
        host: str,
    ) -> None:
        self.findings.append(
            InsecureBindFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
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

    def visit_Call(self, node: ast.Call) -> None:
        self._check_host_keyword(node)
        self._check_bind_call(node)
        self._check_server_address_arg(node)
        self.generic_visit(node)

    def _check_host_keyword(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg != "host":
                continue
            host = _host_from_constant(keyword.value)
            if _is_insecure_host(host):
                self._add_finding(
                    node,
                    pattern="all_interfaces_host",
                    severity="high",
                    message="Binding to all interfaces exposes the service on every network — use 127.0.0.1 or a specific interface",
                    host=host or "",
                )

    def _check_bind_call(self, node: ast.Call) -> None:
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in _BIND_METHODS:
            return
        if not node.args:
            return
        host = _host_from_address_tuple(node.args[0]) or _host_from_constant(node.args[0])
        if _is_insecure_host(host):
            self._add_finding(
                node,
                pattern="all_interfaces_bind",
                severity="high",
                message="Socket bind/listen on all interfaces — restrict to localhost or a specific address",
                host=host or "",
            )

    def _check_server_address_arg(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _SERVER_CALLS:
            callee = func.attr
        elif isinstance(func, ast.Name) and func.id in _SERVER_CALLS:
            callee = func.id
        else:
            return

        if not node.args:
            return
        host = _host_from_address_tuple(node.args[0])
        if _is_insecure_host(host):
            self._add_finding(
                node,
                pattern="all_interfaces_server",
                severity="high",
                message=f"Server {callee}() listening on all interfaces — bind to 127.0.0.1 in development or use a reverse proxy in production",
                host=host or "",
            )


class InsecureBindAnalyzer:
    """Detect services bound to 0.0.0.0, ::, or other all-interface addresses."""

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

    def _scan_source(self, rel: str, source: str) -> list[InsecureBindFinding]:
        findings: list[InsecureBindFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            return findings

        visitor = _InsecureBindVisitor(rel)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return findings

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
            f"Insecure bind addresses: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure bind address analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No all-interface bind addresses found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
