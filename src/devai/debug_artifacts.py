"""DebugArtifactDetector — detect debug statements left in production code."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

# name -> (kind, severity, message)
_DEBUG_BUILTINS: dict[str, tuple[str, str, str]] = {
    "print": (
        "print_statement",
        "medium",
        "print() left in code — use logging or remove before release",
    ),
    "breakpoint": (
        "debugger",
        "high",
        "breakpoint() left in code — remove before release",
    ),
}

_DEBUG_ATTRS: dict[str, tuple[str, str, str]] = {
    "set_trace": (
        "debugger",
        "high",
        "set_trace() left in code — remove before release",
    ),
    "pprint": (
        "print_statement",
        "medium",
        "pprint() left in code — use logging or remove before release",
    ),
    "pp": (
        "print_statement",
        "low",
        "pprint.pp() left in code — use logging or remove before release",
    ),
}

_DEBUG_MODULES = {
    "pdb": {"set_trace"},
    "ipdb": {"set_trace"},
    "pudb": {"set_trace"},
    "debugpy": {"breakpoint"},
}


@dataclass
class DebugArtifact:
    """A debug artifact detected in Python source."""

    path: str
    function: str
    name: str
    lineno: int
    kind: str
    severity: str
    message: str

    def format(self) -> str:
        """Return a single-line description."""
        location = f"{self.function}()" if self.function else "<module>"
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.kind}: "
            f"{location} calls {self.name} — {self.message}"
        )


@dataclass
class DebugArtifactStats:
    """Aggregate debug-artifact statistics."""

    total_findings: int
    by_kind: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_scanned: int = 0
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _debug_from_call(node: ast.Call) -> tuple[str, str, str, str] | None:
    """Return (display_name, kind, severity, message) if the call is a debug artifact."""
    name = _call_name(node)
    if name is None:
        return None

    if isinstance(node.func, ast.Name) and name in _DEBUG_BUILTINS:
        kind, severity, message = _DEBUG_BUILTINS[name]
        return name, kind, severity, message

    if not isinstance(node.func, ast.Attribute):
        return None

    base = node.func.value
    if isinstance(base, ast.Name):
        module = base.id
        if module in _DEBUG_MODULES and name in _DEBUG_MODULES[module]:
            kind, severity, message = _DEBUG_ATTRS.get(
                name,
                ("debugger", "high", f"{module}.{name}() left in code — remove before release"),
            )
            return f"{module}.{name}", kind, severity, message
        if module == "pprint" and name in {"pprint", "pp"}:
            kind, severity, message = _DEBUG_ATTRS[name]
            return f"pprint.{name}", kind, severity, message

    if name in _DEBUG_ATTRS:
        kind, severity, message = _DEBUG_ATTRS[name]
        return name, kind, severity, message

    return None


class _DebugArtifactVisitor(ast.NodeVisitor):
    """Walk a module AST and collect debug artifacts."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[DebugArtifact] = []
        self._function_stack: list[str] = []

    @property
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
        result = _debug_from_call(node)
        if result:
            display_name, kind, severity, message = result
            lineno = getattr(node, "lineno", 1)
            self.findings.append(
                DebugArtifact(
                    path=self.path,
                    function=self._current_function,
                    name=display_name,
                    lineno=lineno,
                    kind=kind,
                    severity=severity,
                    message=message,
                )
            )
        self.generic_visit(node)


class DebugArtifactDetector:
    """Detect debug statements left in Python source code.

    Flags ``print()``, ``pprint()``, ``breakpoint()``, ``pdb.set_trace()``,
    ``ipdb.set_trace()``, and similar debug helpers that should not ship
    to production.
  """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        include_tests: bool = False,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.include_tests = include_tests
        self._findings: list[DebugArtifact] = []
        self._stats: DebugArtifactStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        if path.suffix != ".py":
            return True
        if not self.include_tests:
            parts = set(path.parts)
            if parts & {"tests", "test", "testing"}:
                return True
            if path.name.startswith("test_") or path.name.endswith("_test.py"):
                return True
        return False

    def analyze(self) -> list[DebugArtifact]:
        """Analyze the project and return debug-artifact findings."""
        if self._findings:
            return self._findings

        findings: list[DebugArtifact] = []
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
            visitor = _DebugArtifactVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_kind: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = DebugArtifactStats(
            total_findings=len(findings),
            by_kind=by_kind,
            by_severity=by_severity,
            files_scanned=files_scanned,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> DebugArtifactStats:
        """Return aggregate debug-artifact statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_kind(self, kind: str) -> list[DebugArtifact]:
        """Return findings for a specific kind (e.g. print_statement, debugger)."""
        return [f for f in self.analyze() if f.kind == kind]

    def high_severity(self) -> list[DebugArtifact]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no debug artifacts)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 20.0 + medium * 8.0 + low * 3.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Debug artifacts: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({stats.files_scanned} files scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_kind:
            kinds = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_kind.items()))
            lines.append(f"By kind: {kinds}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing debug artifacts."""
        self.analyze()
        lines = [
            "Debug artifact analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No debug artifacts found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
