"""MassAssignmentAnalyzer — detect unsafe bulk attribute assignment from user input."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_REQUEST_SOURCES = frozenset(
    {
        "request",
        "form",
        "json",
        "data",
        "payload",
        "body",
        "params",
        "query",
        "args",
    }
)
_MODEL_NAMES = frozenset(
    {
        "user",
        "account",
        "profile",
        "model",
        "obj",
        "instance",
        "record",
        "entity",
        "item",
    }
)


@dataclass
class MassAssignmentFinding:
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
class MassAssignmentStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_request_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in _REQUEST_SOURCES
    if isinstance(node, ast.Attribute):
        if node.attr in {"json", "form", "args", "values", "data", "GET", "POST"}:
            return True
        if isinstance(node.value, ast.Name) and node.value.id == "request":
            return True
        return _is_request_source(node.value)
    if isinstance(node, ast.Subscript):
        return _is_request_source(node.value)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "get":
            return _is_request_source(func.value)
    return False


def _is_model_like(name: str) -> bool:
    if name in _MODEL_NAMES:
        return True
    if name.endswith("Model") or name.endswith("_model"):
        return True
    return name[:1].isupper() and name.isidentifier()


class _MassAssignmentVisitor(ast.NodeVisitor):
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
        if isinstance(func, ast.Name) and _is_model_like(func.id):
            if node.args and _is_request_source(node.args[0]):
                self.findings.append(
                    MassAssignmentFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="model_from_request",
                        severity="high",
                        message=f"{func.id}(request data) allows mass assignment of protected fields",
                        function=self._current_function(),
                    )
                )
            if node.keywords and any(_is_request_source(kw.value) for kw in node.keywords):
                self.findings.append(
                    MassAssignmentFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="model_kwargs_from_request",
                        severity="high",
                        message=f"{func.id}(**request data) allows mass assignment of protected fields",
                        function=self._current_function(),
                    )
                )
        if isinstance(func, ast.Attribute):
            if func.attr == "update" and node.args and _is_request_source(node.args[0]):
                self.findings.append(
                    MassAssignmentFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="update_from_request",
                        severity="high",
                        message="update(request data) may assign privileged attributes without an allowlist",
                        function=self._current_function(),
                    )
                )
            if func.attr in {"from_dict", "parse_obj", "model_validate"} and node.args:
                if _is_request_source(node.args[0]):
                    self.findings.append(
                        MassAssignmentFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="schema_from_request",
                            severity="medium",
                            message=f"{func.attr}() with unfiltered request data may allow mass assignment",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if isinstance(node.target, ast.Name) and isinstance(node.iter, ast.Call):
            func = node.iter.func
            if isinstance(func, ast.Attribute) and func.attr in {"items", "keys"}:
                if _is_request_source(node.iter):
                    self.findings.append(
                        MassAssignmentFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="setattr_loop",
                            severity="high",
                            message="Iterating request data for attribute assignment enables mass assignment",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Dict) and _is_request_source(node.value):
            for target in node.targets:
                if isinstance(target, ast.Attribute):
                    self.findings.append(
                        MassAssignmentFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="direct_request_assign",
                            severity="medium",
                            message="Assigning request data directly to object attributes risks mass assignment",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)


class MassAssignmentAnalyzer:
    """Detect mass assignment vulnerabilities from unfiltered user input."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
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

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 15.0 + medium * 8.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Mass assignment risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Mass assignment analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No mass assignment patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
