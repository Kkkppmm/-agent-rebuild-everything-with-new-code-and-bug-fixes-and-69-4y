"""CSRFAnalyzer — detect missing CSRF protection on state-changing web handlers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})
_ROUTE_METHODS = frozenset({"route", "api_route"})
_HTTP_METHOD_DECORATORS = frozenset({"post", "put", "delete", "patch"})
_SAFE_METHOD_DECORATORS = frozenset({"get", "head", "options"})
_CSRF_DECORATORS = frozenset(
    {
        "csrf_protect",
        "requires_csrf_token",
        "ensure_csrf_cookie",
    }
)
_CSRF_EXEMPT_DECORATORS = frozenset({"csrf_exempt", "exempt"})
_CSRF_NAMES = frozenset(
    {
        "CSRFProtect",
        "CsrfViewMiddleware",
        "CSRFMiddleware",
        "csrf_token",
        "validate_csrf",
        "check_csrf",
    }
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
    http_methods: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        methods = f" ({self.http_methods})" if self.http_methods else ""
        return f"{loc}{fn}{methods} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class CSRFStats:
    """Aggregate CSRF analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _decorator_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


def _extract_route_methods(decorator: ast.AST) -> set[str] | None:
    """Return HTTP methods from a route decorator, or None if not a route."""
    name = _decorator_name(decorator)
    if name is None:
        return None

    if name in _HTTP_METHOD_DECORATORS:
        return {name.upper()}
    if name in _SAFE_METHOD_DECORATORS:
        return set()

    if name not in _ROUTE_METHODS:
        return None

    methods: set[str] = set()
    call = decorator if isinstance(decorator, ast.Call) else None
    if call is None:
        return {"GET"}

    for keyword in call.keywords:
        if keyword.arg != "methods":
            continue
        value = keyword.value
        if isinstance(value, (ast.List, ast.Tuple)):
            for elt in value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    methods.add(elt.value.upper())
        elif isinstance(value, ast.Constant) and isinstance(value.value, str):
            methods.add(value.value.upper())

    if not methods:
        return {"GET"}
    return methods


def _has_csrf_decorator(decorators: list[ast.expr]) -> bool:
    for dec in decorators:
        name = _decorator_name(dec)
        if name in _CSRF_DECORATORS:
            return True
    return False


def _has_csrf_exempt(decorators: list[ast.expr]) -> bool:
    for dec in decorators:
        name = _decorator_name(dec)
        if name in _CSRF_EXEMPT_DECORATORS:
            return True
    return False


def _module_has_csrf_setup(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _CSRF_NAMES:
            return True
        if isinstance(node, ast.Attribute) and node.attr in _CSRF_NAMES:
            return True
        if isinstance(node, ast.Call):
            name = _decorator_name(node)
            if name in _CSRF_NAMES:
                return True
    return False


def _function_uses_csrf_token(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id == "csrf_token":
            return True
        if isinstance(child, ast.Attribute) and child.attr in {"csrf_token", "validate_csrf"}:
            return True
        if isinstance(child, ast.Call):
            name = _decorator_name(child)
            if name in {"validate_csrf", "check_csrf"}:
                return True
    return False


class _CSRFVisitor(ast.NodeVisitor):
    """Walk a module AST and collect missing CSRF protection on handlers."""

    def __init__(self, path: str, module_protected: bool) -> None:
        self.path = path
        self.module_protected = module_protected
        self.findings: list[CSRFFinding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_handler(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_handler(node)
        self.generic_visit(node)

    def _check_handler(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if _has_csrf_exempt(node.decorator_list):
            return

        state_methods: set[str] = set()
        for dec in node.decorator_list:
            methods = _extract_route_methods(dec)
            if methods is None:
                continue
            state_methods |= methods & _STATE_CHANGING_METHODS

        if not state_methods:
            return

        if (
            self.module_protected
            or _has_csrf_decorator(node.decorator_list)
            or _function_uses_csrf_token(node)
        ):
            return

        methods_label = ", ".join(sorted(state_methods))
        pattern = "missing_csrf_protection"
        if "POST" in state_methods and len(state_methods) == 1:
            pattern = "unprotected_post_handler"

        self.findings.append(
            CSRFFinding(
                path=self.path,
                lineno=node.lineno,
                pattern=pattern,
                severity="high",
                message="State-changing handler lacks CSRF protection — add csrf_protect or CSRF middleware",
                function=node.name,
                http_methods=methods_label,
            )
        )


class CSRFAnalyzer:
    """Detect missing CSRF protection on state-changing web handlers.

    Flags Flask, Django, and FastAPI/Starlette routes that accept POST, PUT,
    DELETE, or PATCH without csrf_protect decorators or CSRF middleware setup.
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
            module_protected = _module_has_csrf_setup(tree)
            visitor = _CSRFVisitor(rel, module_protected)
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
