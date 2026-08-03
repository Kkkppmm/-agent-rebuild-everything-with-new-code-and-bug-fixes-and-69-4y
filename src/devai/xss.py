"""XSSAnalyzer — detect reflected XSS in web handlers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_REQUEST_SOURCES = frozenset(
    {
        "request",
        "request.args",
        "request.form",
        "request.values",
        "request.GET",
        "request.POST",
        "request.query_params",
        "request.path_params",
    }
)
_HTML_RESPONSE_ATTRS = frozenset(
    {
        "HttpResponse",
        "HTMLResponse",
        "Response",
        "make_response",
        "render_template_string",
        "Markup",
    }
)
_ESCAPE_FUNCS = frozenset({"escape", "html_escape", "markupsafe.escape", "bleach.clean"})


@dataclass
class XSSFinding:
    """A potentially unsafe reflection of user input into HTML output."""

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
        if base and node.attr in {"args", "form", "values", "GET", "POST", "query_params", "path_params"}:
            return True
    if isinstance(node, ast.Subscript):
        return _is_request_access(node.value)
    return _request_source(node) == "request"


def _is_user_controlled(node: ast.AST) -> bool:
    if _is_request_access(node):
        return True
    if isinstance(node, ast.Subscript) and _is_request_access(node.value):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"get", "pop", "getlist"} and _is_request_access(func.value):
                return True
    if isinstance(node, ast.JoinedStr):
        return any(_is_user_controlled(v.value) for v in node.values if isinstance(v, ast.FormattedValue))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_user_controlled(node.left) or _is_user_controlled(node.right)
    if isinstance(node, ast.Name):
        return node.id in {"name", "query", "q", "search", "input", "text", "message", "content", "body"}
    return False


def _is_escaped(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in _ESCAPE_FUNCS:
            return True
        if isinstance(func, ast.Attribute) and func.attr in _ESCAPE_FUNCS:
            return True
    return False


def _is_html_response_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id in _HTML_RESPONSE_ATTRS:
        return True
    if isinstance(func, ast.Attribute) and func.attr in _HTML_RESPONSE_ATTRS:
        return True
    return False


def _classify_xss_call(node: ast.Call) -> tuple[str, str, str] | None:
    func = node.func
    func_name = ""
    if isinstance(func, ast.Attribute):
        func_name = func.attr
    elif isinstance(func, ast.Name):
        func_name = func.id

    if func_name == "render_template_string" and node.args:
        if _is_user_controlled(node.args[0]):
            return (
                "template_string_user_input",
                "high",
                "render_template_string with user-controlled template — use render_template with a fixed file",
            )
        return None

    if func_name == "Markup" and node.args:
        if _is_user_controlled(node.args[0]) and not _is_escaped(node.args[0]):
            return (
                "markup_user_input",
                "high",
                "Markup() wrapping user input without escaping — XSS risk",
            )

    if not _is_html_response_call(node):
        return None

    if not node.args:
        return None

    content_arg = node.args[0]
    if _is_user_controlled(content_arg) and not _is_escaped(content_arg):
        return (
            f"{func_name}_user_content",
            "high",
            "HTML response includes user-controlled content without escaping",
        )

    if isinstance(content_arg, ast.JoinedStr):
        if any(_is_user_controlled(v.value) for v in content_arg.values if isinstance(v, ast.FormattedValue)):
            if not all(
                _is_escaped(v.value)
                for v in content_arg.values
                if isinstance(v, ast.FormattedValue) and _is_user_controlled(v.value)
            ):
                return (
                    "fstring_html_user_input",
                    "high",
                    "f-string HTML response interpolates user input without escaping",
                )

    return None


class _XSSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect reflected XSS risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[XSSFinding] = []
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

    def visit_Return(self, node: ast.Return) -> None:
        if node.value and isinstance(node.value, ast.Call):
            result = _classify_xss_call(node.value)
            if result:
                pattern, severity, message = result
                self.findings.append(
                    XSSFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern=pattern,
                        severity=severity,
                        message=message,
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        result = _classify_xss_call(node)
        if result:
            pattern, severity, message = result
            self.findings.append(
                XSSFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class XSSAnalyzer:
    """Detect reflected XSS vulnerabilities in web framework handlers.

    Flags Flask/Django/FastAPI handlers that reflect user input into HTML
    responses without proper escaping.
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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[XSSFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no XSS risks)."""
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
            f"XSS risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
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
            lines.append("No reflected XSS patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
