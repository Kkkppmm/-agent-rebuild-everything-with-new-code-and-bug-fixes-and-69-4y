"""InsecureTLSAnalyzer — detect disabled TLS certificate verification."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HTTP_MODULES = frozenset({"requests", "httpx", "urllib3", "aiohttp"})
_SSL_INSECURE_ATTRS = frozenset({"CERT_NONE", "PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1"})
_SSL_CONTEXT_METHODS = frozenset({"_create_unverified_context", "create_default_context"})


@dataclass
class InsecureTLSFinding:
    """A disabled or weakened TLS verification pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class InsecureTLSStats:
    """Aggregate insecure TLS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
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


def _kwarg_value(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_false(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _classify_http_call(call: ast.Call) -> tuple[str, str, str] | None:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None

    module = _module_name(func.value)
    if not module:
        return None

    base = module.split(".")[0]
    if base not in _HTTP_MODULES:
        return None

    verify = _kwarg_value(call, "verify")
    if _is_false(verify):
        return (
            "tls_verify_disabled",
            "critical",
            f"{module}.{func.attr}() called with verify=False — TLS certificate validation disabled",
        )

    ssl = _kwarg_value(call, "ssl")
    if _is_false(ssl):
        return (
            "tls_ssl_disabled",
            "critical",
            f"{module}.{func.attr}() called with ssl=False — TLS disabled entirely",
        )

    return None


def _classify_ssl_call(call: ast.Call) -> tuple[str, str, str] | None:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None

    module = _module_name(func.value)
    if module and module.split(".")[0] == "ssl" and func.attr in _SSL_CONTEXT_METHODS:
        if func.attr == "_create_unverified_context":
            return (
                "ssl_unverified_context",
                "critical",
                "ssl._create_unverified_context() disables all certificate verification",
            )

    return None


def _classify_ssl_attribute(node: ast.Attribute) -> tuple[str, str, str] | None:
    module = _module_name(node)
    if module and module.split(".")[0] == "ssl" and node.attr in _SSL_INSECURE_ATTRS:
        if node.attr == "CERT_NONE":
            return (
                "ssl_cert_none",
                "high",
                "ssl.CERT_NONE disables certificate verification",
            )
        return (
            f"ssl_{node.attr.lower()}",
            "medium",
            f"ssl.{node.attr} uses a deprecated/insecure protocol",
        )

    return None


class _InsecureTLSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure TLS patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureTLSFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, node: ast.AST, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            InsecureTLSFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
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
        for classifier in (_classify_http_call, _classify_ssl_call):
            result = classifier(node)
            if result:
                pattern, severity, message = result
                self._add(node, pattern, severity, message)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        result = _classify_ssl_attribute(node)
        if result:
            pattern, severity, message = result
            self._add(node, pattern, severity, message)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            for classifier in (_classify_http_call, _classify_ssl_call):
                result = classifier(node.value)
                if result:
                    pattern, severity, message = result
                    self._add(node.value, pattern, severity, message)
        self.generic_visit(node)


class InsecureTLSAnalyzer:
    """Detect disabled TLS certificate verification in HTTP clients.

    Flags ``verify=False`` in requests/httpx/aiohttp calls, unverified SSL
    contexts, and use of deprecated SSL protocol constants.
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
        """Analyze the project and return insecure TLS findings."""
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

    def critical_findings(self) -> list[InsecureTLSFinding]:
        """Return only critical-severity findings."""
        return [f for f in self.analyze() if f.severity == "critical"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no TLS issues)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = critical * 30.0 + high * 15.0 + medium * 8.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Insecure TLS: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing insecure TLS findings."""
        self.analyze()
        lines = [
            "Insecure TLS analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No insecure TLS patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
