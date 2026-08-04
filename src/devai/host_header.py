"""HostHeaderAnalyzer — detect host header injection risks."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HOST_ATTRS = frozenset({"host", "url_root", "base_url", "HTTP_HOST"})
_REDIRECT_ATTRS = frozenset({"redirect", "Redirect", "redirect_to", "HttpResponseRedirect"})
_URL_BUILD_ATTRS = frozenset({"url_for", "build_absolute_uri", "absolute_url"})


@dataclass
class HostHeaderFinding:
    """A potentially unsafe use of the Host header."""

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
class HostHeaderStats:
    """Aggregate host-header analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_host_access(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in _HOST_ATTRS:
        return True
    if isinstance(node, ast.Subscript):
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            if node.slice.value in {"Host", "HTTP_HOST", "host"}:
                return True
        return _is_host_access(node.value)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "get":
            return _is_host_access(func.value)
    return False


def _contains_host_access(node: ast.AST) -> bool:
    if _is_host_access(node):
        return True
    for child in ast.walk(node):
        if child is not node and _is_host_access(child):
            return True
    return False


def _call_attr(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


class _HostHeaderVisitor(ast.NodeVisitor):
    """Walk a module AST and collect host-header injection risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[HostHeaderFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            HostHeaderFinding(
                path=self.path,
                lineno=node.lineno,
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

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        if any(_contains_host_access(value) for value in node.values):
            self._add(
                node,
                "host_in_fstring",
                severity="high",
                message="URL built from Host header via f-string — validate against an allowlist",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        attr = _call_attr(node)
        if attr in _REDIRECT_ATTRS and node.args and _contains_host_access(node.args[0]):
            self._add(
                node,
                "host_in_redirect",
                severity="high",
                message="Redirect uses Host header — vulnerable to host header injection",
            )
        if attr in _URL_BUILD_ATTRS:
            for arg in node.args:
                if _contains_host_access(arg):
                    self._add(
                        node,
                        "host_in_url_build",
                        severity="medium",
                        message="URL construction uses Host header without validation",
                    )
        if attr == "format" and node.func and isinstance(node.func, ast.Attribute):
            if _contains_host_access(node):
                self._add(
                    node,
                    "host_in_format",
                    severity="high",
                    message="URL built from Host header via .format() — validate against an allowlist",
                )
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.Add):
            if _contains_host_access(node.left) or _contains_host_access(node.right):
                self._add(
                    node,
                    "host_in_concat",
                    severity="medium",
                    message="URL concatenation uses Host header — validate against an allowlist",
                )
        self.generic_visit(node)


class HostHeaderAnalyzer:
    """Detect host header injection risks in web application code.

    Flags redirects and URL construction that incorporate request host values
    without validation, which can enable cache poisoning and password reset attacks.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[HostHeaderFinding] = []
        self._stats: HostHeaderStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[HostHeaderFinding]:
        """Analyze the project and return host-header findings."""
        if self._findings:
            return self._findings

        findings: list[HostHeaderFinding] = []
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
            visitor = _HostHeaderVisitor(rel)
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

        self._stats = HostHeaderStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> HostHeaderStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no host-header risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Host header risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing host-header findings."""
        self.analyze()
        lines = [
            "Host header analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No host-header patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
