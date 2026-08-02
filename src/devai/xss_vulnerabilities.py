"""XssVulnerabilityAnalyzer — detect cross-site scripting risks in web frameworks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SAFE_FILTER_RE = re.compile(r"\|\s*safe\b", re.IGNORECASE)
_AUTOESCAPE_FALSE_RE = re.compile(r"autoescape\s*=\s*False", re.IGNORECASE)


@dataclass
class XssVulnerabilityFinding:
    """A detected XSS vulnerability pattern."""

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
class XssVulnerabilityStats:
    """Aggregate XSS vulnerability analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


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


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


class _XssVisitor(ast.NodeVisitor):
    """Walk a module AST and collect XSS vulnerability patterns."""

    def __init__(self, path: str, source_lines: list[str]) -> None:
        self.path = path
        self.source_lines = source_lines
        self.findings: list[XssVulnerabilityFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        severity: str,
        message: str,
        call: str = "",
    ) -> None:
        self.findings.append(
            XssVulnerabilityFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
                call=call,
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
        name = _call_name(node)
        if name in {"mark_safe", "django.utils.safestring.mark_safe"}:
            self._add(
                node,
                "mark_safe",
                "high",
                "mark_safe() bypasses HTML escaping — ensure input is sanitized",
                call=name,
            )

        func = node.func
        if isinstance(func, ast.Name) and func.id == "Environment":
            for kw in node.keywords:
                if kw.arg == "autoescape" and _is_false(kw.value):
                    self._add(
                        node,
                        "jinja_autoescape_disabled",
                        "high",
                        "Jinja2 Environment with autoescape=False allows unescaped HTML",
                        call=name,
                    )
        elif isinstance(func, ast.Attribute) and func.attr == "Environment":
            for kw in node.keywords:
                if kw.arg == "autoescape" and _is_false(kw.value):
                    self._add(
                        node,
                        "jinja_autoescape_disabled",
                        "high",
                        "Jinja2 Environment with autoescape=False allows unescaped HTML",
                        call=name,
                    )

        if isinstance(func, ast.Name) and func.id == "TemplateResponse":
            for kw in node.keywords:
                if kw.arg == "autoescape" and _is_false(kw.value):
                    self._add(
                        node,
                        "template_autoescape_disabled",
                        "high",
                        "TemplateResponse with autoescape=False disables XSS protection",
                        call=name,
                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for kw in node.keywords if hasattr(node, "keywords") else []:
            pass
        self.generic_visit(node)

    def visit_Module(self, node: ast.Module) -> None:
        for i, line in enumerate(self.source_lines, start=1):
            if _SAFE_FILTER_RE.search(line):
                self.findings.append(
                    XssVulnerabilityFinding(
                        path=self.path,
                        lineno=i,
                        pattern="template_safe_filter",
                        severity="high",
                        message="|safe template filter bypasses HTML escaping",
                    )
                )
            if _AUTOESCAPE_FALSE_RE.search(line) and "autoescape" in line.lower():
                if "False" in line:
                    self.findings.append(
                        XssVulnerabilityFinding(
                            path=self.path,
                            lineno=i,
                            pattern="autoescape_disabled",
                            severity="high",
                            message="autoescape=False disables automatic HTML escaping",
                        )
                    )
        self.generic_visit(node)


class XssVulnerabilityAnalyzer:
    """Detect cross-site scripting risks in Python web projects.

    Flags mark_safe(), |safe template filters, autoescape=False in Jinja2
    and Django templates, and related XSS bypass patterns.
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
        return path.suffix not in {".py", ".html", ".jinja", ".j2"}

    def analyze(self) -> list[XssVulnerabilityFinding]:
        """Analyze the project and return XSS vulnerability findings."""
        if self._findings:
            return self._findings

        findings: list[XssVulnerabilityFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        patterns = ("*.py", "*.html", "*.jinja", "*.j2")
        paths: list[Path] = []
        for pattern in patterns:
            paths.extend(self.root.rglob(pattern))

        for path in sorted(set(paths)):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            source_lines = source.splitlines()

            if path.suffix == ".py":
                try:
                    tree = ast.parse(source, filename=str(path))
                except SyntaxError:
                    continue
                visitor = _XssVisitor(rel, source_lines)
                visitor.visit(tree)
                if visitor.findings:
                    files_with_findings.add(rel)
                findings.extend(visitor.findings)
            else:
                for i, line in enumerate(source_lines, start=1):
                    if _SAFE_FILTER_RE.search(line):
                        findings.append(
                            XssVulnerabilityFinding(
                                path=rel,
                                lineno=i,
                                pattern="template_safe_filter",
                                severity="high",
                                message="|safe template filter bypasses HTML escaping",
                            )
                        )
                        files_with_findings.add(rel)
                    if _AUTOESCAPE_FALSE_RE.search(line):
                        findings.append(
                            XssVulnerabilityFinding(
                                path=rel,
                                lineno=i,
                                pattern="autoescape_disabled",
                                severity="high",
                                message="autoescape=False disables automatic HTML escaping",
                            )
                        )
                        files_with_findings.add(rel)

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
        penalty = high * 20.0
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
            lines.append("No XSS bypass patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
