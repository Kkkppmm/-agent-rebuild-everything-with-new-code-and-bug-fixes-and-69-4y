"""InsecureTLSAnalyzer — detect disabled TLS/SSL certificate verification."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HTTP_CLIENT_ATTRS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "Session", "Client", "AsyncClient"}
)
_SSL_UNSAFE_ATTRS = frozenset({"CERT_NONE", "PROTOCOL_SSLv23", "PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1"})
_SSL_UNSAFE_FUNCS = frozenset({"_create_unverified_context", "wrap_socket"})


@dataclass
class InsecureTLSFinding:
    """A detected TLS/SSL verification bypass."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""
    call: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        call = f" ({self.call})" if self.call else ""
        return f"{loc}{fn}{call} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class InsecureTLSStats:
    """Aggregate insecure-TLS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_http_client_call(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    return node.func.attr in _HTTP_CLIENT_ATTRS


class _InsecureTLSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect TLS verification bypasses."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureTLSFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        *,
        pattern: str,
        severity: str,
        message: str,
        call: str = "",
    ) -> None:
        self.findings.append(
            InsecureTLSFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
                call=call,
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
        for kw in node.keywords:
            if kw.arg == "verify" and _is_false(kw.value):
                call = _call_name(node)
                self._add(
                    node,
                    pattern="verify_false",
                    severity="high",
                    message="TLS certificate verification disabled — vulnerable to MITM attacks",
                    call=call,
                )
            if kw.arg == "check_hostname" and _is_false(kw.value):
                self._add(
                    node,
                    pattern="check_hostname_false",
                    severity="high",
                    message="SSL hostname checking disabled — vulnerable to MITM attacks",
                    call=_call_name(node),
                )

        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in _SSL_UNSAFE_FUNCS:
                if isinstance(func.value, ast.Name) and func.value.id == "ssl":
                    self._add(
                        node,
                        pattern="unverified_context",
                        severity="high",
                        message="ssl._create_unverified_context() disables certificate verification",
                        call=f"ssl.{func.attr}",
                    )
            if func.attr in _SSL_UNSAFE_ATTRS:
                if isinstance(func.value, ast.Name) and func.value.id == "ssl":
                    self._add(
                        node,
                        pattern="weak_ssl_protocol",
                        severity="medium",
                        message=f"ssl.{func.attr} uses an outdated or insecure SSL/TLS protocol",
                        call=f"ssl.{func.attr}",
                    )

        if _is_http_client_call(node):
            for kw in node.keywords:
                if kw.arg == "cert" and isinstance(kw.value, ast.Constant) and kw.value.value is None:
                    self._add(
                        node,
                        pattern="cert_none",
                        severity="medium",
                        message="Client certificate set to None — may skip mutual TLS authentication",
                        call=_call_name(node),
                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Attribute):
            if (
                isinstance(node.value.value, ast.Name)
                and node.value.value.id == "ssl"
                and node.value.attr in _SSL_UNSAFE_ATTRS
            ):
                self._add(
                    node,
                    pattern="weak_ssl_protocol",
                    severity="medium",
                    message=f"ssl.{node.value.attr} assigned — uses an outdated or insecure SSL/TLS protocol",
                    call=f"ssl.{node.value.attr}",
                )
        self.generic_visit(node)


class InsecureTLSAnalyzer:
    """Detect disabled TLS/SSL certificate verification in HTTP clients.

    Flags ``verify=False`` in requests/httpx calls, unverified SSL contexts,
    and disabled hostname checking.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureTLSFinding] = []
        self._stats: InsecureTLSStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[InsecureTLSFinding]:
        """Analyze the project and return insecure-TLS findings."""
        if self._findings:
            return self._findings

        findings: list[InsecureTLSFinding] = []
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
            visitor = _InsecureTLSVisitor(rel)
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

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = InsecureTLSStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureTLSStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[InsecureTLSFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure TLS patterns)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Insecure TLS risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing insecure-TLS findings."""
        self.analyze()
        lines = [
            "Insecure TLS analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No TLS verification bypasses found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
