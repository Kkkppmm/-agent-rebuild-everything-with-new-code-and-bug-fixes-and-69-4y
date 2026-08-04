"""ClickjackingAnalyzer — detect missing clickjacking protections in web apps."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_FRAME_PROTECTION_HEADERS = frozenset(
    {
        "X-Frame-Options",
        "Content-Security-Policy",
        "x-frame-options",
        "content-security-policy",
    }
)
_FRAME_ANCESTORS_RE = re.compile(r"frame-ancestors", re.IGNORECASE)
_HTML_RESPONSE_ATTRS = frozenset(
    {
        "render_template",
        "render_template_string",
        "TemplateResponse",
        "HTMLResponse",
        "render",
    }
)


@dataclass
class ClickjackingFinding:
    """A missing or weak clickjacking protection."""

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
class ClickjackingStats:
    """Aggregate clickjacking analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_attr(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _header_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _has_frame_protection(value: str) -> bool:
    return bool(_FRAME_ANCESTORS_RE.search(value))


class _ClickjackingVisitor(ast.NodeVisitor):
    """Walk a module AST and collect clickjacking risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ClickjackingFinding] = []
        self._function_stack: list[str] = []
        self._has_frame_header = False
        self._serves_html = False

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
            ClickjackingFinding(
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

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.targets[0], ast.Subscript):
            target = node.targets[0]
            header = _header_name(target.slice)
            value = None
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                value = node.value.value
            if header in _FRAME_PROTECTION_HEADERS:
                if header and header.lower() == "content-security-policy":
                    if value and _has_frame_protection(value):
                        self._has_frame_header = True
                else:
                    self._has_frame_header = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        attr = _call_attr(node)
        if attr in _HTML_RESPONSE_ATTRS:
            self._serves_html = True

        if attr in {"setdefault", "add_header", "set_header", "__setitem__"}:
            header = None
            value = None
            if node.args:
                header = _header_name(node.args[0])
            if len(node.args) > 1:
                value_node = node.args[1]
                if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                    value = value_node.value
            if header in _FRAME_PROTECTION_HEADERS:
                if header and header.lower() == "content-security-policy":
                    if value and _has_frame_protection(value):
                        self._has_frame_header = True
                else:
                    self._has_frame_header = True

        if attr == "DENY" and isinstance(node.func, ast.Attribute):
            if node.func.attr == "XFrameOptions":
                self._has_frame_header = True

        self.generic_visit(node)

    def finalize(self) -> None:
        if self._serves_html and not self._has_frame_header:
            self.findings.append(
                ClickjackingFinding(
                    path=self.path,
                    lineno=1,
                    pattern="missing_frame_protection",
                    severity="medium",
                    message=(
                        "HTML responses without X-Frame-Options or CSP frame-ancestors "
                        "are vulnerable to clickjacking"
                    ),
                )
            )


class ClickjackingAnalyzer:
    """Detect missing clickjacking protections in web application code.

    Flags HTML-rendering endpoints that do not set X-Frame-Options or
    Content-Security-Policy frame-ancestors headers.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[ClickjackingFinding] = []
        self._stats: ClickjackingStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[ClickjackingFinding]:
        """Analyze the project and return clickjacking findings."""
        if self._findings:
            return self._findings

        findings: list[ClickjackingFinding] = []
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
            visitor = _ClickjackingVisitor(rel)
            visitor.visit(tree)
            visitor.finalize()
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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no clickjacking risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = medium * 15.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Clickjacking risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing clickjacking findings."""
        self.analyze()
        lines = [
            "Clickjacking analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No clickjacking patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
