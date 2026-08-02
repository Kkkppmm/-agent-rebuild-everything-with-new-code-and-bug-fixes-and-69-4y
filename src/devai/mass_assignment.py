"""MassAssignmentAnalyzer — detect ORM mass-assignment from request data."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_REQUEST_SOURCES = frozenset(
    {
        "request",
        "request.form",
        "request.args",
        "request.values",
        "request.json",
        "request.data",
        "request.POST",
        "request.GET",
        "request.body",
    }
)
_ORM_CREATE_METHODS = frozenset({"create", "update", "update_or_create", "get_or_create"})
_ORM_BULK_METHODS = frozenset({"bulk_create", "bulk_update"})


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
    """Aggregate mass-assignment statistics."""

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


def _is_request_data(node: ast.AST) -> bool:
    source = _request_source(node)
    if source in _REQUEST_SOURCES:
        return True
    if isinstance(node, ast.Dict) and node.keys:
        return any(_is_request_data(k) or _is_request_data(v) for k, v in zip(node.keys, node.values))
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "getlist", "to_dict", "dict"}:
            return _is_request_data(func.value)
    if isinstance(node, ast.Subscript):
        return _is_request_data(node.value)
    return False


def _is_dict_unpacking(node: ast.AST) -> bool:
    return isinstance(node, ast.Dict) and any(k is None for k in node.keys)


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
        func = node.func

        if isinstance(func, ast.Attribute) and func.attr in _ORM_CREATE_METHODS:
            for arg in node.args:
                if _is_dict_unpacking(arg) or _is_request_data(arg):
                    self.findings.append(
                        MassAssignmentFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="orm_create_request_data",
                            severity="high",
                            message=f"ORM {func.attr}() with request data — whitelist allowed fields",
                            function=self._current_function(),
                        )
                    )
            for kw in node.keywords:
                if kw.arg is None and _is_request_data(kw.value):
                    self.findings.append(
                        MassAssignmentFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="orm_create_request_data",
                            severity="high",
                            message=f"ORM {func.attr}() unpacks request data — whitelist allowed fields",
                            function=self._current_function(),
                        )
                    )
                if kw.arg in {"defaults", "data"} and _is_request_data(kw.value):
                    self.findings.append(
                        MassAssignmentFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="orm_kwarg_request_data",
                            severity="high",
                            message=f"ORM {func.attr}() passes request data via {kw.arg}",
                            function=self._current_function(),
                        )
                    )

        if isinstance(func, ast.Name) and func.id in {"User", "Model"}:
            for arg in node.args:
                if _is_dict_unpacking(arg) or _is_request_data(arg):
                    self.findings.append(
                        MassAssignmentFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="model_ctor_request_data",
                            severity="high",
                            message="Model constructor with request data — validate fields explicitly",
                            function=self._current_function(),
                        )
                    )

        if isinstance(func, ast.Attribute) and func.attr == "objects":
            pass  # handled via chained create/update above

        if isinstance(func, ast.Attribute) and func.attr in _ORM_BULK_METHODS:
            for arg in node.args[1:] if len(node.args) > 1 else node.args:
                if _is_request_data(arg):
                    self.findings.append(
                        MassAssignmentFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="orm_bulk_request_data",
                            severity="high",
                            message=f"ORM {func.attr}() with request-derived records",
                            function=self._current_function(),
                        )
                    )

        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for value in node.values:
            if _is_dict_unpacking(value) and _is_request_data(value):
                self.findings.append(
                    MassAssignmentFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="dict_unpack_request",
                        severity="medium",
                        message="Dictionary unpacks request data — may pass untrusted keys",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class MassAssignmentAnalyzer:
    """Detect ORM mass-assignment vulnerabilities from request data.

    Flags ``Model.objects.create(**request.json)``, SQLAlchemy updates from
    ``request.form``, and similar patterns that pass user input directly to ORMs.
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
