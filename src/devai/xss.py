"""XSSAnalyzer — detect cross-site scripting risks in HTML rendering."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|name|comment|message|content|body|text|title|"
    r"query|param|data|payload|value|field|html|output)",
    re.IGNORECASE,
)

_HTML_RESPONSE_ATTRS = frozenset(
    {
        "render_template_string",
        "render_template",
        "Markup",
        "make_response",
        "HTMLResponse",
        "HttpResponse",
        "Template",
        "from_string",
    }
)
_SAFE_ESCAPE_ATTRS = frozenset({"escape", "markupsafe.escape", "html.escape", "cgi.escape"})


@dataclass
class XSSFinding:
    """A potentially unsafe HTML rendering pattern."""

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
class XSSStats:
    """Aggregate XSS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _looks_like_user_input(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return bool(_USER_INPUT_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_USER_INPUT_RE.search(node.attr))
    if isinstance(node, ast.Subscript):
        return _looks_like_user_input(node.value)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {"get", "pop", "getlist"} and _is_request_access(node.func.value):
                return True
            if node.func.attr in {"get", "pop", "getlist"}:
                return _looks_like_user_input(node.func.value)
    return False


def _is_request_access(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and node.id == "request":
        return True
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and node.value.id == "request":
            return node.attr in {"args", "form", "values", "GET", "POST", "query_params", "path_params"}
        return _is_request_access(node.value)
    if isinstance(node, ast.Subscript):
        return _is_request_access(node.value)
    return False


def _is_user_controlled(node: ast.AST) -> bool:
    if _is_request_access(node):
        return True
    if _looks_like_user_input(node):
        return True
    if isinstance(node, ast.JoinedStr):
        return any(
            _is_user_controlled(v.value) for v in node.values if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_user_controlled(node.left) or _is_user_controlled(node.right)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"get", "pop", "getlist"} and _is_request_access(func.value):
                return True
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return any(_is_user_controlled(arg) for arg in node.args)
    return False


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


def _is_html_fstring(node: ast.JoinedStr) -> bool:
    """Detect f-strings that embed HTML tags with user-controlled values."""
    has_html_tag = False
    has_user_input = False
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            if re.search(r"<[a-zA-Z][^>]*>", value.value):
                has_html_tag = True
        if isinstance(value, ast.FormattedValue) and _is_user_controlled(value.value):
            has_user_input = True
    return has_html_tag and has_user_input


def _classify_xss_call(node: ast.Call) -> tuple[str, str, str] | None:
    name = _call_name(node)
    attr = name.split(".")[-1] if name else ""

    if attr == "render_template_string" and node.args:
        if any(_is_user_controlled(arg) for arg in node.args):
            return (
                "template_string_user_input",
                "high",
                "render_template_string with user input can enable XSS — use autoescape or sanitize",
            )

    if attr == "Markup" and node.args:
        if any(_is_user_controlled(arg) for arg in node.args):
            return (
                "markup_user_input",
                "high",
                "Markup() bypasses autoescape — never wrap user-controlled strings",
            )

    if attr in {"HTMLResponse", "HttpResponse"} and node.args:
        if any(_is_user_controlled(arg) for arg in node.args):
            return (
                "html_response_user_input",
                "high",
                "HTML response built from user input without escaping — use a template engine with autoescape",
            )

    if attr == "from_string" and node.args:
        if any(_is_user_controlled(arg) for arg in node.args):
            return (
                "jinja_from_string_user_input",
                "high",
                "Jinja2 Template.from_string with user input — disable autoescape risk",
            )

    if attr == "Template" and isinstance(node.func, ast.Name) and node.args:
        if any(_is_user_controlled(arg) for arg in node.args):
            return (
                "django_template_user_input",
                "medium",
                "Django Template with user-controlled source — validate template content",
            )

    return None


class _XSSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect XSS risks."""

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

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        if _is_html_fstring(node):
            self.findings.append(
                XSSFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="html_fstring_user_input",
                    severity="high",
                    message="HTML f-string embeds user-controlled values — escape before rendering",
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
                    call=_call_name(node),
                )
            )
        self.generic_visit(node)


class XSSAnalyzer:
    """Detect cross-site scripting risks in Python web applications.

    Flags render_template_string, Markup with user input, HTML responses
    built from request data, and f-strings that embed HTML with user values.
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
            lines.append("No XSS patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
