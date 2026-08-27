"""ClickjackingAnalyzer — detect missing clickjacking protections in web applications."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_FRAME_OPTIONS = frozenset({"X-Frame-Options", "x-frame-options"})
_CSP_FRAME = re.compile(r"frame-ancestors|Content-Security-Policy", re.IGNORECASE)
_ROUTE_DECORATORS = frozenset({"route", "get", "post", "api_route", "app"})


@dataclass
class ClickjackingFinding:
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
class ClickjackingStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _decorator_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


class _ClickjackingVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ClickjackingFinding] = []
        self._has_frame_protection = False
        self._has_web_handlers = False
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        if any(_decorator_name(d) in _ROUTE_DECORATORS for d in node.decorator_list):
            self._has_web_handlers = True
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        if any(_decorator_name(d) in _ROUTE_DECORATORS for d in node.decorator_list):
            self._has_web_handlers = True
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"set", "add", "setdefault"}:
            if len(node.args) >= 2:
                header = node.args[0]
                if isinstance(header, ast.Constant) and header.value in _FRAME_OPTIONS:
                    self._has_frame_protection = True
        self.generic_visit(node)


class ClickjackingAnalyzer:
    """Detect web apps missing X-Frame-Options or CSP frame-ancestors headers."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[ClickjackingFinding] = []
        self._stats: ClickjackingStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> bool:
        for line in source.splitlines():
            if _CSP_FRAME.search(line):
                return True
        return False

    def analyze(self) -> list[ClickjackingFinding]:
        if self._findings:
            return self._findings

        findings: list[ClickjackingFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()
        project_has_handlers = False
        project_has_protection = False

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
            visitor = _ClickjackingVisitor(rel)
            visitor.visit(tree)
            has_csp = self._scan_line_patterns(rel, source)
            if visitor._has_web_handlers:
                project_has_handlers = True
            if visitor._has_frame_protection or has_csp:
                project_has_protection = True

        if project_has_handlers and not project_has_protection:
            findings.append(
                ClickjackingFinding(
                    path=".",
                    lineno=1,
                    pattern="missing_frame_protection",
                    severity="medium",
                    message="Web handlers found without X-Frame-Options or CSP frame-ancestors",
                )
            )
            files_with_findings.add(".")

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = ClickjackingStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> ClickjackingStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if not self._findings:
            return 100.0
        return 70.0

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Clickjacking risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Clickjacking analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No clickjacking risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
