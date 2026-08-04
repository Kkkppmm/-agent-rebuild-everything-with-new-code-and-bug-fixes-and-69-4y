"""HostHeaderAnalyzer — detect host header injection in URL construction."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HOST_ATTRS = frozenset({"host", "hostname", "netloc", "HTTP_HOST", "SERVER_NAME"})
_URL_BUILDERS = frozenset({"url_for", "redirect", "build_absolute_uri", "get_host"})


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


def _is_host_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in _HOST_ATTRS:
        return True
    if isinstance(node, ast.Subscript):
        val = node.value
        if isinstance(val, ast.Attribute) and val.attr in {"headers", "environ", "META"}:
            return True
        if isinstance(val, ast.Name) and val.id in {"request", "headers", "environ"}:
            slice_node = node.slice
            if isinstance(slice_node, ast.Constant) and slice_node.value in _HOST_ATTRS:
                return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "get_host"}:
            if isinstance(func.value, ast.Attribute) and func.value.attr in {"headers", "request"}:
                return True
    return False


class _HostHeaderVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[HostHeaderFinding] = []
        self._current_fn = "<module>"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._current_fn = node.name
        self.generic_visit(node)
        self._current_fn = "<module>"

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._current_fn = node.name
        self.generic_visit(node)
        self._current_fn = "<module>"

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name: str | None = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name in _URL_BUILDERS or name == "redirect":
            for arg in node.args:
                if _is_host_value(arg):
                    self.findings.append(
                        HostHeaderFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="host_redirect" if name == "redirect" else "host_in_url_build",
                            severity="high",
                            message=(
                                "Redirect based on unvalidated Host header"
                                if name == "redirect"
                                else f"Host header value used in {name}() without validation"
                            ),
                            function=self._current_fn,
                        )
                    )
                    break

        if isinstance(func, ast.Attribute) and func.attr in {"format", "join"}:
            if _is_host_value(func.value) or any(_is_host_value(a) for a in node.args):
                self.findings.append(
                    HostHeaderFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="host_in_string_build",
                        severity="high",
                        message="Host header used in URL string construction",
                        function=self._current_fn,
                    )
                )


        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        for value in node.values:
            if isinstance(value, ast.FormattedValue) and _is_host_value(value.value):
                self.findings.append(
                    HostHeaderFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="host_in_fstring",
                        severity="high",
                        message="Host header interpolated into URL f-string",
                        function=self._current_fn,
                    )
                )
        self.generic_visit(node)


class HostHeaderAnalyzer:
    """Detect use of Host header in redirects and URL building without validation."""

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
        penalty = high * 15.0
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
            lines.append("No host header injection patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
