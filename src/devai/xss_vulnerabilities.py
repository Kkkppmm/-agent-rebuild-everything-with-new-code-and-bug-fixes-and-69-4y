"""XssVulnerabilityAnalyzer — detect XSS risks from unsafe HTML rendering."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_MARK_SAFE_NAMES = frozenset({"mark_safe", "Markup", "safe"})
_AUTOESCAPE_FALSE = re.compile(r"autoescape\s*=\s*False", re.IGNORECASE)
_SAFE_FILTER = re.compile(r"\{\{[^}]*\|\s*safe\s*\}\}", re.IGNORECASE)


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
    """Aggregate XSS vulnerability statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_user_controlled(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and node.id in {"request", "user_input", "content", "html", "body"}:
        return True
    if isinstance(node, ast.Attribute):
        base = node.value
        if isinstance(base, ast.Name) and base.id == "request":
            return node.attr in {"args", "form", "values", "GET", "POST", "data", "json"}
    if isinstance(node, ast.Subscript):
        return _is_user_controlled(node.value)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "getlist"}:
            return _is_user_controlled(func.value)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(v, ast.FormattedValue) and _is_user_controlled(v.value) for v in node.values
        )
    return False


class _XssVisitor(ast.NodeVisitor):
    """Walk a module AST and collect XSS risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[XssVulnerabilityFinding] = []
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
        name = ""
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name in _MARK_SAFE_NAMES:
            arg = node.args[0] if node.args else None
            severity = "high" if arg and _is_user_controlled(arg) else "medium"
            message = (
                "mark_safe/Markup on user-controlled content disables escaping"
                if severity == "high"
                else "mark_safe/Markup disables HTML escaping — ensure input is trusted"
            )
            self.findings.append(
                XssVulnerabilityFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=f"{name}_call",
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                )
            )

        if isinstance(func, ast.Attribute) and func.attr == "Environment":
            for kw in node.keywords:
                if kw.arg == "autoescape" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.findings.append(
                        XssVulnerabilityFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="jinja_autoescape_false",
                            severity="high",
                            message="Jinja2 Environment with autoescape=False — enable autoescaping",
                            function=self._current_function(),
                        )
                    )

        self.generic_visit(node)


class XssVulnerabilityAnalyzer:
    """Detect XSS risks from mark_safe, |safe filters, and disabled autoescaping.

    Flags Django ``mark_safe()``, Jinja2 ``|safe`` filters, ``autoescape=False``,
    and Flask ``Markup`` usage that may render untrusted HTML.
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
        return path.suffix not in {".py", ".html", ".jinja", ".jinja2", ".j2"}

    def _scan_template(self, path: Path, rel: str) -> list[XssVulnerabilityFinding]:
        findings: list[XssVulnerabilityFinding] = []
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return findings

        for lineno, line in enumerate(source.splitlines(), start=1):
            if _SAFE_FILTER.search(line):
                findings.append(
                    XssVulnerabilityFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="jinja_safe_filter",
                        severity="high",
                        message="Jinja |safe filter disables HTML escaping — sanitize input first",
                    )
                )
            if _AUTOESCAPE_FALSE.search(line):
                findings.append(
                    XssVulnerabilityFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="template_autoescape_false",
                        severity="high",
                        message="Template disables autoescaping — enable autoescape",
                    )
                )
        return findings

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
            files_scanned += 1

            if path.suffix == ".py":
                try:
                    source = path.read_text(encoding="utf-8")
                    tree = ast.parse(source, filename=str(path))
                except (OSError, UnicodeDecodeError, SyntaxError):
                    continue
                visitor = _XssVisitor(rel)
                visitor.visit(tree)
                file_findings = visitor.findings
            else:
                file_findings = self._scan_template(path, rel)

            if file_findings:
                files_with_findings.add(rel)
            findings.extend(file_findings)

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
        """Build LLM-ready context describing XSS findings."""
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
