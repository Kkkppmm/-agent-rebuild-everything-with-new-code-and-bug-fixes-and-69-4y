"""MassAssignmentAnalyzer — detect ORM mass-assignment from request data."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_REQUEST_SOURCES = frozenset(
    {
        "request",
        "request.json",
        "request.form",
        "request.args",
        "request.values",
        "request.data",
        "request.GET",
        "request.POST",
        "request.body",
        "request.query_params",
    }
)

_MASS_ASSIGN_METHODS = frozenset(
    {
        "update",
        "create",
        "bulk_create",
        "get_or_create",
        "update_or_create",
        "objects.create",
        "objects.update",
        "objects.bulk_create",
    }
)


@dataclass
class MassAssignmentFinding:
    """A detected mass-assignment vulnerability."""

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


def _is_request_data(node: ast.AST) -> bool:
    source = _request_source(node)
    if source and source in _REQUEST_SOURCES:
        return True
    if isinstance(node, ast.Starred) and _is_request_data(node.value):
        return True
    if isinstance(node, ast.Subscript) and _is_request_data(node.value):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"get", "getlist", "dict", "to_dict", "json"}:
                base = _request_source(func.value)
                if base and base.startswith("request"):
                    return True
    if isinstance(node, ast.Dict) and node.keys:
        return False
    if isinstance(node, ast.Name) and node.id in {"data", "form_data", "json_data", "payload", "body"}:
        return True
    return False


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


def _is_mass_assign_call(name: str) -> bool:
    short = name.split(".")[-1] if name else ""
    if short in _MASS_ASSIGN_METHODS:
        return True
    if "objects.create" in name or "objects.update" in name:
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

    def _add(self, lineno: int, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            MassAssignmentFinding(
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
        name = _call_name(node)

        if _is_mass_assign_call(name):
            for arg in node.args:
                if _is_request_data(arg):
                    self._add(
                        node.lineno,
                        "request_to_orm",
                        "high",
                        f"Passing request data directly to {name}() — use explicit field allowlists",
                    )
                if isinstance(arg, ast.Starred) and _is_request_data(arg.value):
                    self._add(
                        node.lineno,
                        "request_unpack",
                        "high",
                        f"Unpacking request data into {name}() — whitelist allowed fields",
                    )
            for kw in node.keywords:
                if kw.arg in {"defaults", "data", "fields", "kwargs"} and _is_request_data(kw.value):
                    self._add(
                        node.lineno,
                        "request_kwargs",
                        "high",
                        f"Request data passed as {kw.arg}= to {name}() — whitelist allowed fields",
                    )
                if kw.arg is None and _is_request_data(kw.value):
                    self._add(
                        node.lineno,
                        "request_unpack",
                        "high",
                        f"Unpacking request data into {name}() — whitelist allowed fields",
                    )

        # Model(**request.json) pattern
        if isinstance(node.func, ast.Name) and node.func.id[0].isupper():
            for arg in node.args:
                if _is_request_data(arg):
                    self._add(
                        node.lineno,
                        "model_unpack",
                        "high",
                        "Unpacking request data into model constructor — whitelist fields",
                    )
            for kw in node.keywords:
                if _is_request_data(kw.value):
                    self._add(
                        node.lineno,
                        "model_kwarg",
                        "medium",
                        f"Request data passed as {kw.arg}= to model constructor",
                    )

        self.generic_visit(node)


class MassAssignmentAnalyzer:
    """Detect ORM mass-assignment from request data.

    Flags patterns like ``Model.objects.create(**request.json)``,
    ``model.update(request.form)``, and unpacking request data into
    model constructors without field allowlists.
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
        """Return aggregate mass-assignment statistics."""
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
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Mass assignment: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
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
            lines.append("No mass-assignment risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
