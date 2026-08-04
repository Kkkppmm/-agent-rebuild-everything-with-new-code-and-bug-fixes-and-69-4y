"""BrokenAuthAnalyzer — detect web route handlers missing authentication decorators."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_ROUTE_DECORATORS = frozenset({"route", "get", "post", "put", "patch", "delete", "api_route"})
_AUTH_DECORATORS = frozenset(
    {
        "login_required",
        "requires_auth",
        "authenticated",
        "auth_required",
        "require_auth",
        "jwt_required",
        "token_required",
        "permission_required",
        "roles_required",
        "authorize",
        "requires_login",
        "user_required",
        "Depends",
    }
)
_PUBLIC_MARKERS = frozenset({"public", "allow_anonymous", "anonymous", "skip_auth", "no_auth"})
_SENSITIVE_NAMES = frozenset(
    {
        "admin",
        "delete",
        "update",
        "create",
        "edit",
        "remove",
        "destroy",
        "settings",
        "account",
        "profile",
        "password",
        "billing",
        "payment",
        "secret",
        "internal",
        "manage",
        "export",
        "import",
    }
)


@dataclass
class BrokenAuthFinding:
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
class BrokenAuthStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


def _is_route_decorator(node: ast.expr) -> bool:
    name = _decorator_name(node)
    if name in _ROUTE_DECORATORS:
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _ROUTE_DECORATORS:
            return True
        if isinstance(func, ast.Name) and func.id in {"app", "router", "bp", "blueprint"}:
            return False
    return False


def _has_auth_decorator(decorators: list[ast.expr]) -> bool:
    for dec in decorators:
        name = _decorator_name(dec)
        if name in _AUTH_DECORATORS:
            return True
        if name in _PUBLIC_MARKERS:
            return True
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg in {"dependencies", "deps"}:
                    return True
    return False


def _is_sensitive_handler(name: str, route_path: str | None) -> bool:
    combined = f"{name} {route_path or ''}".lower()
    return any(marker in combined for marker in _SENSITIVE_NAMES)


def _extract_route_path(decorator: ast.expr) -> str | None:
    if not isinstance(decorator, ast.Call):
        return None
    if decorator.args and isinstance(decorator.args[0], ast.Constant):
        val = decorator.args[0].value
        if isinstance(val, str):
            return val
    return None


class _BrokenAuthVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[BrokenAuthFinding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_handler(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_handler(node)
        self.generic_visit(node)

    def _check_handler(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        route_decorators = [d for d in node.decorator_list if _is_route_decorator(d)]
        if not route_decorators:
            return
        if _has_auth_decorator(node.decorator_list):
            return

        route_path = None
        for dec in route_decorators:
            route_path = _extract_route_path(dec) or route_path

        if not _is_sensitive_handler(node.name, route_path):
            return

        self.findings.append(
            BrokenAuthFinding(
                path=self.path,
                lineno=node.lineno,
                pattern="missing_auth_decorator",
                severity="high",
                message=f"Route handler '{node.name}' appears sensitive but has no authentication decorator",
                function=node.name,
            )
        )


class BrokenAuthAnalyzer:
    """Detect web route handlers that likely need authentication but lack auth decorators."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[BrokenAuthFinding] = []
        self._stats: BrokenAuthStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[BrokenAuthFinding]:
        if self._findings:
            return self._findings

        findings: list[BrokenAuthFinding] = []
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
            visitor = _BrokenAuthVisitor(rel)
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
        self._stats = BrokenAuthStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> BrokenAuthStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 20.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Broken auth risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Broken auth analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No broken auth patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
