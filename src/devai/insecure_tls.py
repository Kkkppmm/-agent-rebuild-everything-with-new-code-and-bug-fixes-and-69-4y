"""InsecureTLSAnalyzer — detect disabled TLS certificate verification."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HTTP_ATTRS = frozenset({"get", "post", "put", "patch", "delete", "head", "request", "fetch"})
_HTTP_MODULES = frozenset({"requests", "httpx", "aiohttp", "urllib3", "http"})


@dataclass
class InsecureTLSFinding:
    """A potentially unsafe TLS/SSL configuration."""

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
    """Aggregate insecure TLS statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _kw_bool(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _attr_chain(node: ast.AST) -> list[str]:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return list(reversed(parts))


def _is_http_call(node: ast.Call) -> bool:
    chain = _attr_chain(node.func)
    if not chain:
        return False
    if chain[0] in _HTTP_MODULES:
        return True
    if len(chain) >= 2 and chain[-1] in _HTTP_ATTRS:
        return chain[0] in _HTTP_MODULES or chain[-2] in _HTTP_MODULES
    return False


def _check_call(node: ast.Call, path: str, function: str) -> list[InsecureTLSFinding]:
    findings: list[InsecureTLSFinding] = []
    kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}

    if _is_http_call(node):
        verify = _kw_bool(kwargs.get("verify"))
        if verify is False:
            findings.append(
                InsecureTLSFinding(
                    path=path,
                    lineno=node.lineno,
                    pattern="verify_false",
                    severity="critical",
                    message="HTTP client called with verify=False — TLS certificate validation disabled",
                    function=function,
                )
            )
        ssl_val = _kw_bool(kwargs.get("ssl"))
        if ssl_val is False:
            findings.append(
                InsecureTLSFinding(
                    path=path,
                    lineno=node.lineno,
                    pattern="ssl_false",
                    severity="critical",
                    message="HTTP client called with ssl=False — TLS disabled or unverified",
                    function=function,
                )
            )

    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == "create_default_context":
        chain = _attr_chain(func)
        if chain and chain[0] == "ssl":
            for kw in node.keywords:
                if kw.arg == "check_hostname" and _kw_bool(kw.value) is False:
                    findings.append(
                        InsecureTLSFinding(
                            path=path,
                            lineno=node.lineno,
                            pattern="check_hostname_false",
                            severity="high",
                            message="SSL context created with check_hostname=False",
                            function=function,
                        )
                    )

    if isinstance(func, ast.Attribute) and func.attr == "_create_unverified_context":
        chain = _attr_chain(func)
        if chain and chain[0] == "ssl":
            findings.append(
                InsecureTLSFinding(
                    path=path,
                    lineno=node.lineno,
                    pattern="unverified_context",
                    severity="critical",
                    message="ssl._create_unverified_context() disables certificate verification",
                    function=function,
                )
            )

    return findings


def _check_attribute(node: ast.Attribute, path: str, function: str) -> list[InsecureTLSFinding]:
    chain = _attr_chain(node)
    if chain == ["ssl", "CERT_NONE"]:
        return [
            InsecureTLSFinding(
                path=path,
                lineno=node.lineno,
                pattern="cert_none",
                severity="high",
                message="ssl.CERT_NONE disables certificate validation",
                function=function,
            )
        ]
    return []


class _TLSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure TLS patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureTLSFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        self.findings.extend(_check_call(node, self.path, self._current_function()))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.findings.extend(_check_attribute(node, self.path, self._current_function()))
        self.generic_visit(node)


class InsecureTLSAnalyzer:
    """Detect disabled TLS certificate verification in HTTP clients.

    Flags ``verify=False`` in requests/httpx, ``ssl=False`` in aiohttp,
    ``ssl._create_unverified_context()``, ``ssl.CERT_NONE``, and
    ``check_hostname=False`` in SSL context creation.
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
            visitor = _TLSVisitor(rel)
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
        """Return critical and high-severity findings."""
        return [f for f in self.analyze() if f.severity in {"critical", "high"}]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure TLS)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = critical * 30.0 + high * 15.0
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
