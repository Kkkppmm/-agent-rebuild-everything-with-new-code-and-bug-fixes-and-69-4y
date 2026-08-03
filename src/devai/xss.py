"""XSSAnalyzer — detect reflected XSS risks in web handlers."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|param|query|form|data|payload|name|value|text|"
    r"message|content|body|search|q|term|comment|title|html|raw)",
    re.IGNORECASE,
)

_RESPONSE_FUNCS = frozenset({
    "render_template_string",
    "HTMLResponse",
    "HttpResponse",
    "make_response",
    "Markup",
    "safe",
    "jsonify",
})


@dataclass
class XSSFinding:
    """A potentially unsafe HTML output pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        fn = f" in {self.function}" if self.function else ""
        return f"{self.path}:{self.lineno}{fn} [{self.severity}] {self.pattern}: {self.message}"


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
            return _looks_like_user_input(node.func)
    return False


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(
            _looks_like_user_input(v.value)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _looks_like_user_input(node.left) or _looks_like_user_input(node.right)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return any(_looks_like_user_input(arg) for arg in node.args)
    return _looks_like_user_input(node)


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


class _XSSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect XSS risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[XSSFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
        function: str = "",
    ) -> None:
        self.findings.append(
            XSSFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=function,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name in _RESPONSE_FUNCS and node.args:
            first_arg = node.args[0]
            if _is_dynamic_string(first_arg) or _looks_like_user_input(first_arg):
                self._add(
                    node,
                    "unescaped_html_output",
                    severity="high",
                    message="User input rendered without escaping — use auto-escaping templates or markupsafe.escape()",
                    function=name,
                )
        if name == "Markup" and node.args:
            if _looks_like_user_input(node.args[0]):
                self._add(
                    node,
                    "markup_user_input",
                    severity="high",
                    message="Markup() disables auto-escaping on user-controlled data",
                    function=name,
                )
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value and _is_dynamic_string(node.value):
            self._add(
                node,
                "dynamic_html_return",
                severity="medium",
                message="Dynamic string returned — verify output is escaped before rendering",
            )
        self.generic_visit(node)


class XSSAnalyzer:
    """Detect reflected XSS risks in Python web handlers.

    Flags ``render_template_string``, ``Markup``, and ``HTMLResponse`` calls
    that include user-controlled input without escaping.
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

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
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
        """Return a 0-100 health score (100 = no XSS risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"XSS risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing XSS findings."""
        self.analyze()
        lines = ["XSS analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No XSS risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
