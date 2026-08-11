"""ProxyTrustAnalyzer — detect unvalidated trust of proxy headers for client IP."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_PROXY_HEADERS = frozenset(
    {
        "x_forwarded_for",
        "x_real_ip",
        "x_forwarded_proto",
        "x_forwarded_host",
        "forwarded",
        "http_x_forwarded_for",
        "http_x_real_ip",
        "http_x_forwarded_host",
        "http_x_forwarded_proto",
    }
)

_PROXY_HEADER_RE = re.compile(
    r"(?i)(x-forwarded-for|x-real-ip|x-forwarded-proto|x-forwarded-host|"
    r"forwarded|http_x_forwarded_for|http_x_real_ip|http_x_forwarded_host|"
    r"http_x_forwarded_proto)"
)

_SECURITY_CONTEXT_NAMES = frozenset(
    {
        "allow",
        "allowed",
        "whitelist",
        "block",
        "deny",
        "auth",
        "authenticate",
        "admin",
        "ip",
        "client_ip",
        "remote_addr",
        "check_ip",
        "is_allowed",
        "verify_ip",
    }
)


@dataclass
class ProxyTrustFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class ProxyTrustStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _normalize_header(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _is_proxy_header_constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        normalized = _normalize_header(node.value)
        return normalized in _PROXY_HEADERS
    return False


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _contains_security_context(node: ast.AST) -> bool:
    for child in ast.walk(node):
        name = None
        if isinstance(child, ast.Name):
            name = child.id
        elif isinstance(child, ast.Attribute):
            name = child.attr
        if name and name.lower() in _SECURITY_CONTEXT_NAMES:
            return True
    return False


class _ProxyTrustVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ProxyTrustFinding] = []
        self._function_stack: list[str] = []
        self._tainted_names: set[str] = set()

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add_finding(
        self,
        node: ast.AST,
        *,
        pattern: str,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            ProxyTrustFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 1),
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self._tainted_names = set()
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self._tainted_names = set()
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._expr_uses_proxy_header(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted_names.add(target.id)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _is_proxy_header_constant(node.slice):
            severity = "high" if _contains_security_context(node) else "medium"
            self._add_finding(
                node,
                pattern="proxy_header_access",
                severity=severity,
                message="Proxy header read without validation — spoofable by clients",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name == "get" and node.args and _is_proxy_header_constant(node.args[0]):
            severity = "high" if _contains_security_context(node) else "medium"
            self._add_finding(
                node,
                pattern="proxy_header_access",
                severity=severity,
                message="Proxy header read without validation — spoofable by clients",
            )
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {"split", "strip"}:
            if self._expr_uses_proxy_header(node.func.value):
                self._add_finding(
                    node,
                    pattern="proxy_header_client_ip",
                    severity="high",
                    message="Client IP derived from proxy header — validate trusted proxy hops",
                )
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        if self._compare_uses_proxy_header(node):
            self._add_finding(
                node,
                pattern="proxy_header_auth",
                severity="high",
                message="Proxy header used in access control — attackers can spoof client IP",
            )
        self.generic_visit(node)

    def _is_tainted_name(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id in self._tainted_names

    def _arg_uses_proxy_header(self, node: ast.AST) -> bool:
        if self._is_tainted_name(node):
            return True
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name == "get" and node.args and _is_proxy_header_constant(node.args[0]):
                return True
        if isinstance(node, ast.Subscript) and _is_proxy_header_constant(node.slice):
            return True
        return False

    def _compare_uses_proxy_header(self, node: ast.Compare) -> bool:
        for side in (node.left, *node.comparators):
            if self._expr_uses_proxy_header(side):
                return True
        return False

    def _expr_uses_proxy_header(self, node: ast.AST) -> bool:
        if self._arg_uses_proxy_header(node):
            return True
        if isinstance(node, ast.Call) and _call_name(node) in {"split", "strip"}:
            return self._expr_uses_proxy_header(node.func.value)
        return False


class ProxyTrustAnalyzer:
    """Detect unvalidated trust of X-Forwarded-For and related proxy headers."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[ProxyTrustFinding] = []
        self._stats: ProxyTrustStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[ProxyTrustFinding]:
        findings: list[ProxyTrustFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            return findings

        visitor = _ProxyTrustVisitor(rel)
        visitor.visit(tree)
        findings.extend(visitor.findings)

        for match in _PROXY_HEADER_RE.finditer(source):
            line_no = source.count("\n", 0, match.start()) + 1
            line = source.splitlines()[line_no - 1] if line_no <= len(source.splitlines()) else ""
            if line.strip().startswith("#"):
                continue
            if any(f.lineno == line_no for f in findings):
                continue
            findings.append(
                ProxyTrustFinding(
                    path=rel,
                    lineno=line_no,
                    pattern="proxy_header_literal",
                    severity="medium",
                    message="Proxy header reference detected — ensure trusted proxy validation",
                )
            )
        return findings

    def analyze(self) -> list[ProxyTrustFinding]:
        if self._findings:
            return self._findings

        findings: list[ProxyTrustFinding] = []
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
        self._stats = ProxyTrustStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> ProxyTrustStats:
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
            f"Proxy trust risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Proxy trust analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No unvalidated proxy header trust found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
