"""CSRFAnalyzer — detect missing CSRF protection on state-changing handlers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})
_CSRF_DECORATORS = frozenset(
    {
        "csrf_protect",
        "csrf_exempt",
        "ensure_csrf_cookie",
        "requires_csrf_token",
        "validate_csrf",
    }
)
_CSRF_IMPORTS = frozenset({"csrf", "csrf_protect", "CSRFProtect"})


@dataclass
class CSRFFinding:
    """A state-changing handler that may lack CSRF protection."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""
    method: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        method = f" [{self.method}]" if self.method else ""
        return f"{loc}{fn}{method} [{self.severity}] {self.pattern}: {self.message}"


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
        if isinstance(dec, ast.Name) and dec.id in _CSRF_DECORATORS:
            return True
        if isinstance(dec, ast.Attribute) and dec.attr in _CSRF_DECORATORS:
            return True
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Name) and func.id in _CSRF_DECORATORS:
                return True
            if isinstance(func, ast.Attribute) and func.attr in _CSRF_DECORATORS:
                return True
    return False


def _extract_route_methods(decorators: list[ast.expr]) -> list[str]:
    methods: list[str] = []
    for dec in decorators:
        if not isinstance(dec, ast.Call):
            continue
        func = dec.func
        route_name = None
        if isinstance(func, ast.Attribute) and func.attr in {"route", "post", "put", "delete", "patch", "api_route"}:
            route_name = func.attr
        elif isinstance(func, ast.Name) and func.id in {"route", "post", "put", "delete", "patch"}:
            route_name = func.id

        if route_name is None:
            continue

        if route_name in {"post", "put", "delete", "patch"}:
            methods.append(route_name.upper())
            continue

        for kw in dec.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        methods.append(elt.value.upper())
    return methods


def _is_state_changing(methods: list[str]) -> bool:
    return bool(methods and any(m in _STATE_CHANGING_METHODS for m in methods))


class _CSRFVisitor(ast.NodeVisitor):
    """Walk a module AST and collect missing CSRF protection risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[CSRFFinding] = []
        self._has_csrf_import = False
        self._function_stack: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name.split(".")[0] in _CSRF_IMPORTS or "csrf" in alias.name.lower():
                self._has_csrf_import = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and "csrf" in node.module.lower():
            self._has_csrf_import = True
        for alias in node.names:
            if alias.name in _CSRF_DECORATORS or "csrf" in alias.name.lower():
                self._has_csrf_import = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self._check_handler(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self._check_handler(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def _check_handler(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        methods = _extract_route_methods(node.decorator_list)
        if not _is_state_changing(methods):
            return
        if _has_csrf_decorator(node.decorator_list):
            return

        method_str = ",".join(sorted(set(methods)))
        self.findings.append(
            CSRFFinding(
                path=self.path,
                lineno=node.lineno,
                pattern="missing_csrf_protection",
                severity="high",
                message="State-changing route handler lacks CSRF protection decorator",
                function=self._function_stack[-1],
                method=method_str,
            )
        )


class CSRFAnalyzer:
    """Detect missing CSRF protection on state-changing web handlers.

    Flags Flask/Django/FastAPI route handlers for POST, PUT, DELETE, and PATCH
    that do not use csrf_protect or equivalent decorators.
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

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[CSRFFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no CSRF risks)."""
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
            f"CSRF risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing CSRF findings."""
        self.analyze()
        lines = [
            "CSRF analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No missing CSRF protection patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
