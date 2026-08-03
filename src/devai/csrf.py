"""CSRFAnalyzer — detect missing CSRF protection on state-changing handlers."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_ROUTE_METHODS = frozenset({"post", "put", "patch", "delete"})
_CSRF_DECORATORS = frozenset({
    "csrf_protect",
    "csrf_exempt",
    "requires_csrf_token",
    "ensure_csrf_cookie",
    "csrf",
})
_STATE_CHANGING_RE = re.compile(
    r"(create|update|delete|remove|save|submit|register|login|logout|upload|"
    r"modify|edit|destroy|insert|write|send|post|put|patch)",
    re.IGNORECASE,
)


@dataclass
class CSRFFinding:
    """A state-changing handler without CSRF protection."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""
    method: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        fn = f" {self.function}" if self.function else ""
        method = f" [{self.method.upper()}]" if self.method else ""
        return (
            f"{self.path}:{self.lineno}{method}{fn} [{self.severity}] "
            f"{self.pattern}: {self.message}"
        )


@dataclass
class CSRFStats:
    """Aggregate CSRF analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _has_csrf_decorator(decorators: list[ast.expr]) -> bool:
    for dec in decorators:
        name = ""
        if isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Attribute):
            name = dec.attr
        elif isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                name = dec.func.id
            elif isinstance(dec.func, ast.Attribute):
                name = dec.func.attr
        if name in _CSRF_DECORATORS:
            return True
    return False


def _route_methods(decorators: list[ast.expr]) -> list[str]:
    methods: list[str] = []
    for dec in decorators:
        if not isinstance(dec, ast.Call):
            continue
        func = dec.func
        if isinstance(func, ast.Attribute) and func.attr == "route":
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            methods.append(elt.value.lower())
        if isinstance(func, ast.Attribute) and func.attr in _ROUTE_METHODS:
            methods.append(func.attr)
        if isinstance(func, ast.Name) and func.id in _ROUTE_METHODS:
            methods.append(func.id)
    return methods


def _is_state_changing(name: str) -> bool:
    return bool(_STATE_CHANGING_RE.search(name))


class _CSRFVisitor(ast.NodeVisitor):
    """Walk a module AST and collect missing CSRF protection."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[CSRFFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
        function: str = "",
        method: str = "",
    ) -> None:
        self.findings.append(
            CSRFFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=function,
                method=method,
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        methods = _route_methods(node.decorator_list)
        state_changing = _is_state_changing(node.name)
        has_csrf = _has_csrf_decorator(node.decorator_list)

        for method in methods:
            if method in _ROUTE_METHODS and not has_csrf:
                self._add(
                    node,
                    "missing_csrf_protection",
                    severity="high",
                    message="State-changing route without CSRF protection",
                    function=node.name,
                    method=method,
                )
        if state_changing and methods and not has_csrf and not self.findings:
            self._add(
                node,
                "state_changing_no_csrf",
                severity="medium",
                message="Handler name suggests state change — verify CSRF token validation",
                function=node.name,
                method=methods[0] if methods else "",
            )
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        methods = _route_methods(node.decorator_list)
        has_csrf = _has_csrf_decorator(node.decorator_list)
        for method in methods:
            if method in _ROUTE_METHODS and not has_csrf:
                self._add(
                    node,
                    "missing_csrf_protection",
                    severity="high",
                    message="State-changing route without CSRF protection",
                    function=node.name,
                    method=method,
                )
        self.generic_visit(node)


class CSRFAnalyzer:
    """Detect missing CSRF protection on state-changing web handlers.

    Flags POST/PUT/PATCH/DELETE routes without ``csrf_protect`` or equivalent
    decorators in Flask, Django, and FastAPI-style code.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[CSRFFinding] = []
        self._stats: CSRFStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[CSRFFinding]:
        """Analyze the project and return CSRF findings."""
        if self._findings:
            return self._findings

        findings: list[CSRFFinding] = []
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
            visitor = _CSRFVisitor(rel)
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
        self._stats = CSRFStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> CSRFStats:
        """Return aggregate CSRF statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[CSRFFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no CSRF issues)."""
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
            f"CSRF risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing CSRF findings."""
        self.analyze()
        lines = ["CSRF analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No CSRF risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
