"""DebugArtifactDetector — find debug code left in production sources."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_DEBUG_CALLS: dict[str, tuple[str, str, str]] = {
    "breakpoint": ("breakpoint", "medium", "breakpoint() left in code — remove before release"),
    "set_trace": ("pdb", "high", "pdb.set_trace() left in code — remove before release"),
    "print_exc": ("traceback", "low", "traceback.print_exc() — consider structured logging"),
}


@dataclass
class DebugArtifact:
    """A debug artifact found in source code."""

    path: str
    lineno: int
    kind: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.kind}: {self.message}"


@dataclass
class DebugArtifactStats:
    """Aggregate debug artifact statistics."""

    total_findings: int
    by_kind: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


class _DebugArtifactVisitor(ast.NodeVisitor):
    """Walk a module AST and collect debug artifacts."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[DebugArtifact] = []
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

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "pdb":
                self.findings.append(
                    DebugArtifact(
                        path=self.path,
                        lineno=node.lineno,
                        kind="pdb_import",
                        severity="medium",
                        message="pdb imported — often used for debugging",
                        function=self._current_function(),
                    )
                )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "pdb":
            self.findings.append(
                DebugArtifact(
                    path=self.path,
                    lineno=node.lineno,
                    kind="pdb_import",
                    severity="medium",
                    message="pdb imported — often used for debugging",
                    function=self._current_function(),
                )
            )

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name == "print" and isinstance(node.func, ast.Name):
            self.findings.append(
                DebugArtifact(
                    path=self.path,
                    lineno=node.lineno,
                    kind="print",
                    severity="low",
                    message="print() call — consider using logging",
                    function=self._current_function(),
                )
            )
        elif name and name in _DEBUG_CALLS:
            kind, severity, message = _DEBUG_CALLS[name]
            if name == "set_trace":
                if isinstance(node.func, ast.Attribute):
                    value = node.func.value
                    if isinstance(value, ast.Name) and value.id == "pdb":
                        self.findings.append(
                            DebugArtifact(
                                path=self.path,
                                lineno=node.lineno,
                                kind=kind,
                                severity=severity,
                                message=message,
                                function=self._current_function(),
                            )
                        )
            elif name == "print_exc":
                if isinstance(node.func, ast.Attribute):
                    value = node.func.value
                    if isinstance(value, ast.Name) and value.id == "traceback":
                        self.findings.append(
                            DebugArtifact(
                                path=self.path,
                                lineno=node.lineno,
                                kind=kind,
                                severity=severity,
                                message=message,
                                function=self._current_function(),
                            )
                        )
            else:
                self.findings.append(
                    DebugArtifact(
                        path=self.path,
                        lineno=node.lineno,
                        kind=kind,
                        severity=severity,
                        message=message,
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class DebugArtifactDetector:
    """Detect debug artifacts left in Python source code.

    Flags ``print()``, ``breakpoint()``, ``pdb.set_trace()``, and ``pdb`` imports.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[DebugArtifact] = []
        self._stats: DebugArtifactStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[DebugArtifact]:
        """Analyze the project and return debug artifact findings."""
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
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> DebugArtifactStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[DebugArtifact]:
        """Return medium and high severity findings."""
        return [f for f in self.analyze() if f.severity in {"high", "medium"}]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no debug artifacts)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 15.0 + medium * 5.0 + low * 1.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Debug artifacts: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
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
