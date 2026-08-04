"""MassAssignmentAnalyzer — detect mass assignment vulnerabilities in ORM handlers."""

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
        "request.values",
        "request.args",
        "request.data",
        "request.POST",
        "request.GET",
        "request.query_params",
        "request.path_params",
    }
)
_ORM_UPDATE_METHODS = frozenset(
    {
        "update",
        "update_from_dict",
        "from_dict",
        "create",
        "insert",
        "save",
        "merge",
        "bulk_create",
        "bulk_update",
    }
)
_SENSITIVE_FIELDS = frozenset(
    {
        "is_admin",
        "is_staff",
        "is_superuser",
        "role",
        "roles",
        "permissions",
        "password",
        "password_hash",
        "api_key",
        "secret",
        "token",
        "balance",
        "credit",
        "verified",
        "active",
        "status",
        "owner_id",
        "user_id",
        "group_id",
    }
)


@dataclass
class MassAssignmentFinding:
    """A potentially unsafe mass assignment from user input."""

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
    """Aggregate mass assignment analysis statistics."""

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
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "get_json", "getlist", "to_dict"}:
            if _is_request_data(func.value):
                return True
    if isinstance(node, ast.Subscript) and _is_request_data(node.value):
        return True
    if isinstance(node, ast.Name) and node.id in {"data", "payload", "body", "form_data", "json_data"}:
        return True
    return False


def _dict_from_request(node: ast.AST) -> bool:
    if _is_request_data(node):
        return True
    if isinstance(node, ast.Dict):
        return any(_is_request_data(v) for v in node.values)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "dict":
            return any(_is_request_data(arg) for arg in node.args)
        if isinstance(func, ast.Attribute) and func.attr in {"copy", "model_dump", "dict"}:
            return _is_request_data(func.value)
    return False


def _has_request_kwargs(node: ast.Call) -> bool:
    if any(kw.arg is None and _dict_from_request(kw.value) for kw in node.keywords):
        return True
    if any(kw.arg and _is_request_data(kw.value) for kw in node.keywords):
        return True
    return any(_dict_from_request(arg) or _is_request_data(arg) for arg in node.args)


def _model_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _model_name(node.func)
    return ""


def _classify_mass_assignment(node: ast.Call) -> tuple[str, str, str] | None:
    func = node.func

    # Model(**request.json) or Model(**data)
    if isinstance(func, ast.Name) and func.id[0].isupper():
        if _has_request_kwargs(node):
            return (
                "model_from_request_dict",
                "high",
                f"Model {func.id} built from request dict — whitelist assignable fields",
            )

    if isinstance(func, ast.Attribute):
        method = func.attr
        if method in _ORM_UPDATE_METHODS:
            for arg in node.args:
                if _dict_from_request(arg) or _is_request_data(arg):
                    model = _model_name(func.value)
                    return (
                        f"{method}_from_request",
                        "high",
                        f"{model}.{method}() with request data — restrict updatable fields",
                    )
            for kw in node.keywords:
                if kw.arg in _SENSITIVE_FIELDS and _is_request_data(kw.value):
                    return (
                        "sensitive_field_assignment",
                        "critical",
                        f"Sensitive field '{kw.arg}' assigned from request data",
                    )
                if kw.arg == "defaults" and _dict_from_request(kw.value):
                    return (
                        "defaults_from_request",
                        "high",
                        "ORM defaults/update from request dict — use field allowlist",
                    )

        if method == "objects" and isinstance(func.value, ast.Name):
            # User.objects.create(**request.json)
            pass

    if isinstance(func, ast.Attribute) and func.attr == "create":
        parent = func.value
        if isinstance(parent, ast.Attribute) and parent.attr == "objects":
            model = _model_name(parent.value)
            if _has_request_kwargs(node):
                return (
                    "orm_create_from_request",
                    "high",
                    f"{model}.objects.create() with request dict — whitelist fields",
                )

    # setattr loop over request data
    if isinstance(func, ast.Name) and func.id == "setattr":
        if len(node.args) >= 3 and _is_request_data(node.args[2]):
            return (
                "setattr_from_request",
                "high",
                "setattr() with request data — avoid dynamic attribute assignment",
            )

    return None


class _MassAssignmentVisitor(ast.NodeVisitor):
    """Walk a module AST and collect mass assignment risks."""

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

    def visit_For(self, node: ast.For) -> None:
        if isinstance(node.target, ast.Name) and isinstance(node.iter, ast.Call):
            func = node.iter.func
            if isinstance(func, ast.Attribute) and func.attr in {"items", "keys"}:
                if _is_request_data(func.value):
                    self.findings.append(
                        MassAssignmentFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="iterate_request_assign",
                            severity="high",
                            message="Iterating request data for assignment — use explicit field mapping",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)

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
    """Detect mass assignment vulnerabilities in web handlers and ORM code.

    Flags Django/SQLAlchemy/Pydantic patterns where request data is passed
    directly to model constructors, update methods, or ORM create calls.
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
        """Analyze the project and return mass assignment findings."""
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
        """Return high and critical severity findings."""
        return [f for f in self.analyze() if f.severity in {"high", "critical"}]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no mass assignment risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = critical * 30.0 + high * 25.0 + medium * 10.0
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
        """Build LLM-ready context describing mass assignment findings."""
        self.analyze()
        lines = [
            "Mass assignment analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No mass assignment patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
