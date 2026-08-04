"""MassAssignmentAnalyzer — detect bulk updates from untrusted request data."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_UPDATE_METHODS = frozenset({"update", "bulk_update", "update_many", "set"})
_REQUEST_NAMES = frozenset({"request", "req", "data", "body", "payload", "form", "json"})
_DANGEROUS_FIELDS = frozenset({"is_admin", "role", "permissions", "password", "active", "verified"})


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


def _is_request_data(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and node.id in _REQUEST_NAMES:
        return True
    if isinstance(node, ast.Attribute):
        if node.attr in {"data", "form", "json", "args", "values", "GET", "POST"}:
            return True
        return _is_request_data(node.value)
    if isinstance(node, ast.Subscript):
        return _is_request_data(node.value)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "get_json", "to_dict"}:
            return _is_request_data(func.value)
    return False


class _MassAssignmentVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[MassAssignmentFinding] = []
        self._current_fn = "<module>"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._current_fn = node.name
        self.generic_visit(node)
        self._current_fn = "<module>"

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._current_fn = node.name
        self.generic_visit(node)
        self._current_fn = "<module>"

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _UPDATE_METHODS:
            for arg in node.args:
                if _is_request_data(arg):
                    self.findings.append(
                        MassAssignmentFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="bulk_update_from_request",
                            severity="high",
                            message=f"{func.attr}() called with untrusted request data",
                            function=self._current_fn,
                        )
                    )
                    break
                if isinstance(arg, ast.Dict):
                    for key in arg.keys:
                        if isinstance(key, ast.Constant) and key.value in _DANGEROUS_FIELDS:
                            self.findings.append(
                                MassAssignmentFinding(
                                    path=self.path,
                                    lineno=node.lineno,
                                    pattern="dangerous_field_update",
                                    severity="high",
                                    message=f"Dangerous field '{key.value}' in bulk update",
                                    function=self._current_fn,
                                )
                            )
        if isinstance(func, ast.Attribute) and func.attr == "setattr":
            if len(node.args) >= 3 and _is_request_data(node.args[2]):
                self.findings.append(
                    MassAssignmentFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="setattr_from_request",
                        severity="medium",
                        message="setattr() with request-controlled value",
                        function=self._current_fn,
                    )
                )
        self.generic_visit(node)


class MassAssignmentAnalyzer:
    """Detect bulk model/object updates from untrusted request payloads."""

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
                lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
