"""MassAssignmentAnalyzer — detect ORM create/update from user-controlled dicts."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_ORM_METHODS = frozenset({"create", "update", "update_or_create", "bulk_create", "get_or_create"})
_REQUEST_SOURCES = frozenset(
    {
        "request",
        "request.form",
        "request.args",
        "request.values",
        "request.json",
        "request.data",
        "request.GET",
        "request.POST",
        "request.body",
        "request.query_params",
    }
)


@dataclass
class MassAssignmentFinding:
    """A potentially unsafe mass-assignment from user input."""

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
class MassAssignmentStats:
    """Aggregate mass-assignment analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _request_source(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and node.id == "request":
        return "request"
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _is_request_access(node: ast.AST) -> bool:
    src = _request_source(node)
    if src in _REQUEST_SOURCES:
        return True
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base and node.attr in {"form", "args", "values", "json", "data", "GET", "POST", "body", "query_params"}:
            return True
    if isinstance(node, ast.Subscript) and _is_request_access(node.value):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"get_json", "get_data", "dict", "model_dump"} and _is_request_access(func.value):
                return True
            if func.attr in {"get", "getlist", "to_dict"} and _is_request_access(func.value):
                return True
    return False


def _is_user_dict(node: ast.AST) -> bool:
    if _is_request_access(node):
        return True
    if isinstance(node, ast.Dict) and not node.keys:
        # **kwargs unpacking from request
        return False
    if isinstance(node, ast.Starred) and _is_user_dict(node.value):
        return True
    return False


def _classify_mass_assignment(node: ast.Call) -> tuple[str, str, str] | None:
    func = node.func
    method = None
    if isinstance(func, ast.Attribute) and func.attr in _ORM_METHODS:
        method = func.attr
    if method is None:
        return None

    for arg in node.args:
        if isinstance(arg, ast.Dict) and _has_user_controlled_values(arg):
            return (
                f"{method}_user_dict",
                "high",
                f"ORM {method}() with user-controlled dict — whitelist allowed fields",
            )

    for kw in node.keywords:
        if kw.arg is None and _is_user_dict(kw.value):
            return (
                f"{method}_kwargs_unpack",
                "high",
                f"ORM {method}(**request_data) — whitelist allowed fields before assignment",
            )

    # Model(**request.json) constructor pattern
    if isinstance(func, ast.Name) and func.id[0].isupper():
        for kw in node.keywords:
            if kw.arg is None and _is_user_dict(kw.value):
                return (
                    "model_constructor_unpack",
                    "high",
                    "Model instantiated with **user data — validate and filter fields",
                )

    return None


def _has_user_controlled_values(node: ast.Dict) -> bool:
    for value in node.values:
        if _is_request_access(value):
            return True
        if isinstance(value, ast.Call) and _is_request_access(value.func):
            return True
    return False


class _MassAssignmentVisitor(ast.NodeVisitor):
    """Walk a module AST and collect mass-assignment risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[MassAssignmentFinding] = []
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
        result = _classify_mass_assignment(node)
        if result:
            pattern, severity, message = result
            self.findings.append(
                MassAssignmentFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class MassAssignmentAnalyzer:
    """Detect mass-assignment vulnerabilities in ORM code.

    Flags Django ``Model.objects.create(**request.POST)``, SQLAlchemy-style
    ``Model(**request.json)``, and similar patterns where user-controlled
    dictionaries are passed directly to ORM create/update methods.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[MassAssignmentFinding] = []
        self._stats: MassAssignmentStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[MassAssignmentFinding]:
        """Analyze the project and return mass-assignment findings."""
        if self._findings:
            return self._findings

        findings: list[MassAssignmentFinding] = []
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
            visitor = _MassAssignmentVisitor(rel)
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

        self._stats = MassAssignmentStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> MassAssignmentStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[MassAssignmentFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no mass-assignment risks)."""
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
            f"Mass assignment risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing mass-assignment findings."""
        self.analyze()
        lines = [
            "Mass assignment analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No mass-assignment patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
