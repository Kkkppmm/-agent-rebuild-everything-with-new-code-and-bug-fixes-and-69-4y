"""XssVulnerabilityAnalyzer — detect cross-site scripting risks in web code."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_XSS_CALLS = frozenset({"mark_safe", "Markup", "HTML", "SafeString"})
_XSS_ATTRS = frozenset({"mark_safe", "Markup", "HTML", "SafeString", "safe"})
_TEMPLATE_SAFE_RE = re.compile(r"\{\{[^}]*\|\s*safe\s*\}\}")


@dataclass
class XssVulnerabilityFinding:
    """A potentially unsafe HTML rendering pattern."""

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
class XssVulnerabilityStats:
    """Aggregate XSS vulnerability analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _classify_xss_call(node: ast.Call) -> tuple[str, str, str] | None:
    func = node.func
    name = ""
    if isinstance(func, ast.Name) and func.id in _XSS_CALLS:
        name = func.id
    elif isinstance(func, ast.Attribute) and func.attr in _XSS_ATTRS:
        name = func.attr
    if not name:
        return None

    severity = "high" if name in {"mark_safe", "safe"} else "medium"
    return (
        name,
        severity,
        f"Avoid {name}() on untrusted input — use framework auto-escaping instead",
    )


def _classify_autoescape_false(node: ast.keyword) -> tuple[str, str, str] | None:
    if node.arg != "autoescape" or not isinstance(node.value, ast.Constant):
        return None
    if node.value.value is False:
        return (
            "autoescape_false",
            "high",
            "Jinja2 autoescape disabled — enable autoescape for HTML templates",
        )
    return None


class _XssVisitor(ast.NodeVisitor):
    """Walk a module AST and collect XSS vulnerability patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[XssVulnerabilityFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, lineno: int, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            XssVulnerabilityFinding(
                path=self.path,
                lineno=lineno,
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

    def visit_Call(self, node: ast.Call) -> None:
        result = _classify_xss_call(node)
        if result:
            pattern, severity, message = result
            self._add(node.lineno, pattern, severity, message)
        self.generic_visit(node)

    def visit_keyword(self, node: ast.keyword) -> None:
        result = _classify_autoescape_false(node)
        if result:
            pattern, severity, message = result
            self._add(node.lineno or 0, pattern, severity, message)
        self.generic_visit(node)


class XssVulnerabilityAnalyzer:
    """Detect cross-site scripting risks in Python web projects.

    Flags Django ``mark_safe()``, Jinja2 ``|safe`` filters, Werkzeug ``Markup()``,
    and ``autoescape=False`` in template environments.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[XssVulnerabilityFinding] = []
        self._stats: XssVulnerabilityStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix not in {".py", ".html", ".jinja", ".jinja2", ".htm"}

    def _scan_template_line(self, line: str, path: str, lineno: int) -> list[XssVulnerabilityFinding]:
        if not _TEMPLATE_SAFE_RE.search(line):
            return []
        return [
            XssVulnerabilityFinding(
                path=path,
                lineno=lineno,
                pattern="template_safe_filter",
                severity="high",
                message="Jinja2 |safe filter disables escaping — sanitize input first",
            )
        ]

    def analyze(self) -> list[XssVulnerabilityFinding]:
        """Analyze the project and return XSS vulnerability findings."""
        if self._findings:
            return self._findings

        findings: list[XssVulnerabilityFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue
            rel = str(path.relative_to(self.root))
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            if path.suffix == ".py":
                try:
                    tree = ast.parse(source, filename=str(path))
                except SyntaxError:
                    continue
                visitor = _XssVisitor(rel)
                visitor.visit(tree)
                if visitor.findings:
                    files_with_findings.add(rel)
                findings.extend(visitor.findings)
            else:
                for lineno, line in enumerate(source.splitlines(), start=1):
                    line_findings = self._scan_template_line(line, rel, lineno)
                    if line_findings:
                        files_with_findings.add(rel)
                    findings.extend(line_findings)

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

        self._stats = XssVulnerabilityStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> XssVulnerabilityStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[XssVulnerabilityFinding]:
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
            f"XSS vulnerabilities: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing XSS vulnerability findings."""
        self.analyze()
        lines = [
            "XSS vulnerability analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No XSS vulnerability patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
