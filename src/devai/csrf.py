"""CSRFAnalyzer — detect missing CSRF protection on state-changing handlers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_ROUTE_DECORATORS = frozenset({"route", "post", "put", "patch", "delete", "api_route"})
_CSRF_DECORATORS = frozenset({"csrf_protect", "csrf_exempt", "ensure_csrf", "validate_csrf"})


@dataclass
class CSRFFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class CSRFStats:
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


def _is_state_changing_route(decorator: ast.AST) -> bool:
    name = _decorator_name(decorator)
    if name in {"post", "put", "patch", "delete"}:
        return True
    if isinstance(decorator, ast.Call):
        for kw in decorator.keywords:
            if kw.arg == "methods" and isinstance(kw.value, ast.List):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Constant) and elt.value in _STATE_CHANGING_METHODS:
                        return True
        if decorator.args and isinstance(decorator.args[0], ast.Constant):
            if decorator.args[0].value in _STATE_CHANGING_METHODS:
                return True
    return False


def _has_csrf_protection(decorators: list[ast.expr]) -> bool:
    for dec in decorators:
        name = _decorator_name(dec)
        if name in _CSRF_DECORATORS:
            return True
    return False


class _CSRFVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[CSRFFinding] = []
        self._has_csrf_import = False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if "csrf" in alias.name.lower():
                self._has_csrf_import = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and "csrf" in node.module.lower():
            self._has_csrf_import = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_handler(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_handler(node)
        self.generic_visit(node)

    def _check_handler(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        is_state_changing = any(_is_state_changing_route(d) for d in node.decorator_list)
        if not is_state_changing:
            return
        if _has_csrf_protection(node.decorator_list):
            return
        self.findings.append(
            CSRFFinding(
                path=self.path,
                lineno=node.lineno,
                pattern="missing_csrf",
                severity="medium",
                message=f"State-changing handler '{node.name}' lacks CSRF protection",
                function=node.name,
            )
        )


class CSRFAnalyzer:
    """Detect state-changing web handlers without CSRF protection."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"CSRF risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["CSRF analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No missing CSRF protection found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
