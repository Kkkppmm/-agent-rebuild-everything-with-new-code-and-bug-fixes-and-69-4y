"""HostHeaderAnalyzer — detect host header injection in redirects and URL construction."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HOST_ATTRS = frozenset({"host", "hostname", "HTTP_HOST", "server_name"})
_REDIRECT_ATTRS = frozenset({"redirect", "RedirectResponse", "HttpResponseRedirect"})


@dataclass
class HostHeaderFinding:
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
class HostHeaderStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_request_host(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in _HOST_ATTRS:
        if isinstance(node.value, ast.Name) and node.value.id == "request":
            return True
        if isinstance(node.value, ast.Attribute):
            base = node.value
            if isinstance(base.value, ast.Name) and base.value.id == "request":
                return True
    if isinstance(node, ast.Subscript):
        return _is_request_host(node.value)
    return False


class _HostHeaderVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[HostHeaderFinding] = []
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
        func = node.func
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name in _REDIRECT_ATTRS:
            for arg in node.args:
                if _is_request_host(arg) or self._contains_host_ref(arg):
                    self.findings.append(
                        HostHeaderFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="host_in_redirect",
                            severity="high",
                            message="Redirect URL built from request host without validation",
                            function=self._current_function(),
                        )
                    )
                    break
        self.generic_visit(node)

    def _contains_host_ref(self, node: ast.AST) -> bool:
        if _is_request_host(node):
            return True
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue) and _is_request_host(val.value):
                    return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._contains_host_ref(node.left) or self._contains_host_ref(node.right)
        return False


class HostHeaderAnalyzer:
    """Detect redirects and URLs built from unvalidated Host headers."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
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

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 25.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Host header risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Host header analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No host header injection risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
