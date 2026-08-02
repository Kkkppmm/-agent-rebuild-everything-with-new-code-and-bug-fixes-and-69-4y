"""DebugModeAnalyzer — detect debug mode enabled in production code."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_DEBUG_KEYS = frozenset({
    "DEBUG",
    "debug",
    "FLASK_DEBUG",
    "FLASK_ENV",
    "DJANGO_DEBUG",
})
_DEV_ENV_VALUES = frozenset({"development", "dev", "debug"})
_RUN_DEBUG_ATTRS = frozenset({"run", "run_simple"})


@dataclass
class DebugModeFinding:
    """A detected debug-mode-in-production issue."""

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
class DebugModeStats:
    """Aggregate debug-mode analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_true(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value is True:
        return True
    if isinstance(node, ast.NameConstant) and node.value is True:
        return True
    return False


def _is_dev_env(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower() in _DEV_ENV_VALUES
    return False


def _key_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


class _DebugModeVisitor(ast.NodeVisitor):
    """Walk a module AST and collect debug-mode-in-production issues."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[DebugModeFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        *,
        pattern: str,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            DebugModeFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
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

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            name = _key_name(target)
            if name in _DEBUG_KEYS and _is_true(node.value):
                self._add(
                    node,
                    pattern="debug_flag_true",
                    severity="high",
                    message=f"{name}=True exposes stack traces and enables code execution in some frameworks",
                )
            if name in {"FLASK_ENV", "ENV", "APP_ENV"} and _is_dev_env(node.value):
                self._add(
                    node,
                    pattern="dev_environment",
                    severity="medium",
                    message=f"{name} set to development — use production settings in deployed code",
                )
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        key = _key_name(node.slice)
        if key in _DEBUG_KEYS:
            parent = getattr(node, "_parent_value", None)
            if parent is not None and _is_true(parent):
                self._add(
                    node,
                    pattern="debug_config_true",
                    severity="high",
                    message=f'app.config["{key}"]=True enables debug mode in production',
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _RUN_DEBUG_ATTRS:
            for kw in node.keywords:
                if kw.arg == "debug" and _is_true(kw.value):
                    self._add(
                        node,
                        pattern="run_debug_true",
                        severity="high",
                        message="app.run(debug=True) enables the Werkzeug debugger — never use in production",
                    )
        self.generic_visit(node)


class DebugModeAnalyzer:
    """Detect debug mode and development settings in Python web applications.

    Flags DEBUG=True, FLASK_ENV=development, app.run(debug=True), and
    similar patterns that expose sensitive information in production.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[DebugModeFinding] = []
        self._stats: DebugModeStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        if "test" in path.stem.lower():
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[DebugModeFinding]:
        """Analyze the project and return debug-mode findings."""
        if self._findings:
            return self._findings

        findings: list[DebugModeFinding] = []
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
            visitor = _DebugModeVisitor(rel)
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

        self._stats = DebugModeStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> DebugModeStats:
        """Return aggregate debug-mode statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[DebugModeFinding]:
        """Return critical and high severity findings."""
        return [f for f in self.analyze() if f.severity in {"critical", "high"}]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no debug-mode issues)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = critical * 40.0 + high * 25.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        critical = stats.by_severity.get("critical", 0)
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Debug mode: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Critical: {critical}, High: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing debug-mode findings."""
        self.analyze()
        lines = [
            "Debug mode analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No debug-mode issues found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
