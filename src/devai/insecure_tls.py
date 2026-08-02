"""InsecureTLSAnalyzer — detect disabled TLS verification and weak SSL settings."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SSL_UNVERIFIED_ATTRS = frozenset(
    {"CERT_NONE", "PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"}
)
_VERIFY_FALSE_KEYWORDS = frozenset({"verify", "ssl"})
_HTTP_CLIENT_NAMES = frozenset({"session", "client", "http", "async_client", "aiohttp"})


@dataclass
class InsecureTLSFinding:
    """A detected insecure TLS or SSL configuration."""

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
    """Aggregate insecure TLS analysis statistics."""

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


def _receiver_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return ""


class _InsecureTLSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure TLS patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureTLSFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
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
        name = _call_name(node)
        if name in {"ssl._create_unverified_context", "_create_unverified_context"}:
            self._add(
                node,
                "unverified_ssl_context",
                "high",
                "ssl._create_unverified_context() disables certificate verification",
                call=name,
            )

        for kw in node.keywords:
            if kw.arg in _VERIFY_FALSE_KEYWORDS and _is_false(kw.value):
                self._add(
                    node,
                    "verify_disabled",
                    "high",
                    f"{kw.arg}=False disables TLS certificate verification",
                    call=name,
                )

        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr == "create_default_context" and isinstance(func.value, ast.Name):
                if func.value.id == "ssl":
                    for kw in node.keywords:
                        if kw.arg == "purpose" and isinstance(kw.value, ast.Attribute):
                            if kw.value.attr in _SSL_UNVERIFIED_ATTRS:
                                self._add(
                                    node,
                                    "weak_ssl_protocol",
                                    "medium",
                                    f"Using deprecated SSL protocol {kw.value.attr}",
                                    call=name,
                                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                if target.attr in {"check_hostname", "verify_mode"}:
                    if _is_false(node.value):
                        self._add(
                            node,
                            "ssl_context_hardening_disabled",
                            "high",
                            f"ssl context {target.attr} set to False weakens TLS security",
                        )
                    if isinstance(node.value, ast.Attribute) and isinstance(
                        node.value.value, ast.Name
                    ):
                        if node.value.value.id == "ssl" and node.value.attr in _SSL_UNVERIFIED_ATTRS:
                            self._add(
                                node,
                                "weak_ssl_verify_mode",
                                "high",
                                f"ssl verify_mode set to {node.value.attr}",
                            )
        self.generic_visit(node)


class InsecureTLSAnalyzer:
    """Detect disabled TLS verification and weak SSL configuration.

    Flags verify=False, ssl=False, unverified SSL contexts, and deprecated
  protocols in requests, httpx, urllib3, and ssl module usage.
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

    def high_severity(self) -> list[InsecureTLSFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure TLS)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 25.0
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
            lines.append("No disabled TLS verification found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
