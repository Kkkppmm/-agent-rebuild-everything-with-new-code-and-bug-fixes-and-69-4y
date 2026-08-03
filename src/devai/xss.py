"""XSSAnalyzer — detect reflected XSS risks in Python web handlers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HTML_MARKERS = frozenset(
    {
        "<script",
        "<img",
        "<div",
        "<span",
        "<a ",
        "<p>",
        "<h1",
        "<h2",
        "<body",
        "innerhtml",
        "outerhtml",
        "document.write",
    }
)

_ESCAPE_FUNCS = frozenset(
    {
        "escape",
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
        "bleach.clean",
    }
)

_REQUEST_ATTRS = frozenset(
    {
        "args",
        "form",
        "values",
        "GET",
        "POST",
        "query_params",
        "path_params",
        "data",
        "json",
        "cookies",
    }
)


@dataclass
class XSSFinding:
    """A potentially unsafe HTML output with user-controlled data."""

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
class XSSStats:
    """Aggregate XSS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _request_source(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and node.id == "request":
        return "request"
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _is_request_access(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base and node.attr in _REQUEST_ATTRS:
            return True
    if isinstance(node, ast.Subscript) and _is_request_access(node.value):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "get" and _is_request_access(node.func.value):
            return True
    return _request_source(node) == "request"


def _contains_html_marker(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in _HTML_MARKERS)


def _is_escape_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "escape":
            return True
        if isinstance(func, ast.Attribute):
            chain = f"{func.attr}"
            if isinstance(func.value, ast.Attribute):
                parent = func.value
                if isinstance(parent.value, ast.Name):
                    chain = f"{parent.value.id}.{parent.attr}.{func.attr}"
                elif isinstance(parent.value, ast.Name):
                    chain = f"{parent.attr}.{func.attr}"
            if isinstance(func.value, ast.Name):
                chain = f"{func.value.id}.{func.attr}"
            return chain in _ESCAPE_FUNCS or func.attr == "escape"
    return False


def _node_has_user_input(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if _is_request_access(child):
            return True
    return False


class _XSSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect reflected XSS risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[XSSFinding] = []
        self._function_stack: list[str] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            XSSFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._function_stack[-1] if self._function_stack else "",
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

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is None:
            return
        if _node_has_user_input(node.value) and not _is_escape_call(node.value):
            if isinstance(node.value, ast.JoinedStr):
                for part in node.value.values:
                    if isinstance(part, ast.Constant) and _contains_html_marker(str(part.value)):
                        self._add(
                            node,
                            "fstring_html",
                            severity="high",
                            message="F-string HTML output includes request data without escaping",
                        )
                        break
            elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                left = node.value.left
                right = node.value.right
                has_html = False
                if isinstance(left, ast.Constant) and _contains_html_marker(str(left.value)):
                    has_html = True
                if isinstance(right, ast.Constant) and _contains_html_marker(str(right.value)):
                    has_html = True
                if has_html:
                    self._add(
                        node,
                        "concat_html",
                        severity="high",
                        message="HTML concatenation includes request data without escaping",
                    )
            elif isinstance(node.value, ast.Constant) and _contains_html_marker(str(node.value.value)):
                self._add(
                    node,
                    "static_html_with_input",
                    severity="medium",
                    message="Return value mixes HTML markers with user-controlled data",
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"Markup", "mark_safe"} and node.args:
                if _node_has_user_input(node.args[0]) and not _is_escape_call(node.args[0]):
                    self._add(
                        node,
                        "unsafe_markup",
                        severity="high",
                        message="Markup/mark_safe applied to user-controlled data",
                    )
            if func.attr == "render_template_string" and node.args:
                if len(node.args) > 1 and _node_has_user_input(node.args[1]):
                    self._add(
                        node,
                        "template_string",
                        severity="high",
                        message="render_template_string with user-controlled template source",
                    )
            if func.attr in {"HttpResponse", "HTMLResponse"} and node.args:
                arg = node.args[0]
                if _node_has_user_input(arg) and not _is_escape_call(arg):
                    if isinstance(arg, ast.JoinedStr) or isinstance(arg, ast.BinOp):
                        self._add(
                            node,
                            "response_html",
                            severity="high",
                            message="HTTP response body includes unescaped request data",
                        )
        self.generic_visit(node)


class XSSAnalyzer:
    """Detect reflected XSS risks in Python web frameworks.

    Flags f-strings and concatenation that embed request data into HTML,
    unsafe ``Markup()`` / ``mark_safe()`` usage, and dynamic template rendering.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[XSSFinding] = []
        self._stats: XSSStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[XSSFinding]:
        """Analyze the project and return XSS findings."""
        if self._findings:
            return self._findings

        findings: list[XSSFinding] = []
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
            visitor = _XSSVisitor(rel)
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

        self._stats = XSSStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> XSSStats:
        """Return aggregate XSS statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[XSSFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no XSS risks detected)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 12.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"XSS: {stats.total_findings} risks in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing XSS findings."""
        self.analyze()
        lines = [
            "XSS analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No reflected XSS risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
