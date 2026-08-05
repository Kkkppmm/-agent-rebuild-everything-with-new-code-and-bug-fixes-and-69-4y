"""NamingConventionAnalyzer — PEP 8 naming convention checks for Python projects."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SNAKE_CASE = re.compile(r"^[a-z_][a-z0-9_]*$")
_CAP_WORDS = re.compile(r"^[A-Z][a-zA-Z0-9]*(?:_[A-Z][a-zA-Z0-9]*)*$")
_SCREAMING_SNAKE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_DUNDER = re.compile(r"^__\w+__$")


@dataclass
class NamingViolation:
    """A PEP 8 naming convention violation."""

    path: str
    name: str
    lineno: int
    kind: str
    expected: str
    message: str

    def format(self) -> str:
        """Return a single-line description."""
        return (
            f"{self.path}:{self.lineno} [{self.kind}] {self.name} — "
            f"expected {self.expected}: {self.message}"
        )


@dataclass
class NamingStats:
    """Aggregate naming convention statistics."""

    total_violations: int
    by_kind: dict[str, int] = field(default_factory=dict)
    files_with_violations: int = 0
    violation_density: float = 0.0


class _NamingVisitor(ast.NodeVisitor):
    """Walk a module AST and collect naming violations."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.violations: list[NamingViolation] = []
        self._class_stack: list[str] = []
        self._in_class = False

    def _add(
        self,
        node: ast.AST,
        name: str,
        kind: str,
        expected: str,
        message: str,
    ) -> None:
        lineno = getattr(node, "lineno", 1)
        self.violations.append(
            NamingViolation(
                path=self.path,
                name=name,
                lineno=lineno,
                kind=kind,
                expected=expected,
                message=message,
            )
        )

    def _is_dunder(self, name: str) -> bool:
        return bool(_DUNDER.match(name))

    def _is_private(self, name: str) -> bool:
        return name.startswith("_") and not self._is_dunder(name)

    def _check_function_name(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        name: str,
    ) -> None:
        if self._is_dunder(name):
            return
        if self._in_class and name in ("__init__", "__new__", "__call__", "__str__", "__repr__"):
            return
        if not _SNAKE_CASE.match(name):
            self._add(
                node,
                name,
                "function" if not self._in_class else "method",
                "snake_case",
                f"'{name}' should use lowercase_with_underscores",
            )

    def _check_class_name(self, node: ast.ClassDef, name: str) -> None:
        if not _CAP_WORDS.match(name):
            self._add(
                node,
                name,
                "class",
                "CapWords",
                f"'{name}' should use CapWords (PascalCase)",
            )

    def _check_variable_name(
        self,
        node: ast.AST,
        name: str,
        *,
        is_constant: bool = False,
    ) -> None:
        if name == "_" or self._is_dunder(name):
            return
        if is_constant:
            if not _SCREAMING_SNAKE.match(name):
                self._add(
                    node,
                    name,
                    "constant",
                    "SCREAMING_SNAKE_CASE",
                    f"'{name}' should use UPPER_CASE_WITH_UNDERSCORES",
                )
            return
        if self._is_private(name):
            base = name.lstrip("_")
            if base and not _SNAKE_CASE.match(base):
                self._add(
                    node,
                    name,
                    "variable",
                    "snake_case",
                    f"'{name}' should use _lowercase_with_underscores",
                )
            return
        if not _SNAKE_CASE.match(name):
            self._add(
                node,
                name,
                "variable",
                "snake_case",
                f"'{name}' should use lowercase_with_underscores",
            )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._check_class_name(node, node.name)
        self._class_stack.append(node.name)
        prev = self._in_class
        self._in_class = True
        self.generic_visit(node)
        self._in_class = prev
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function_name(node, node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function_name(node, node.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        is_module_level = not self._class_stack
        for target in node.targets:
            if isinstance(target, ast.Name):
                is_constant = is_module_level and isinstance(node.value, ast.Constant)
                self._check_variable_name(
                    node,
                    target.id,
                    is_constant=is_constant,
                )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            self._check_variable_name(node, node.target.id, is_constant=False)
        self.generic_visit(node)


class NamingConventionAnalyzer:
    """Check Python source files for PEP 8 naming convention violations.

    Validates function, method, class, variable, and module-level constant names.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._violations: list[NamingViolation] = []
        self._stats: NamingStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[NamingViolation]:
        """Analyze the project and return naming violations."""
        if self._violations:
            return self._violations

        violations: list[NamingViolation] = []
        files_scanned = 0
        files_with_violations: set[str] = set()

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
            visitor = _NamingVisitor(rel)
            visitor.visit(tree)
            if visitor.violations:
                files_with_violations.add(rel)
            violations.extend(visitor.violations)

        self._violations = violations
        self._files_scanned = files_scanned

        by_kind: dict[str, int] = {}
        for v in violations:
            by_kind[v.kind] = by_kind.get(v.kind, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(violations) / files_scanned, 1)

        self._stats = NamingStats(
            total_violations=len(violations),
            by_kind=by_kind,
            files_with_violations=len(files_with_violations),
            violation_density=density,
        )
        return violations

    @property
    def stats(self) -> NamingStats:
        """Return aggregate naming statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_kind(self, kind: str) -> list[NamingViolation]:
        """Return violations for a specific kind (function, class, variable, etc.)."""
        return [v for v in self.analyze() if v.kind == kind]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no violations)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        ratio = len(self._violations) / self._files_scanned
        class_violations = sum(1 for v in self._violations if v.kind == "class")
        penalty = ratio * 60.0 + class_violations * 5.0
        return round(max(0.0, 100.0 - penalty), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Naming: {stats.total_violations} violations in "
            f"{stats.files_with_violations} files ({self._files_scanned} scanned)",
            f"Density: {stats.violation_density} violations per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_kind:
            kinds = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_kind.items()))
            lines.append(f"By kind: {kinds}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing naming violations."""
        self.analyze()
        lines = [
            "Naming convention analysis:",
            self.summary(),
            "",
            "Violations:",
        ]
        if not self._violations:
            lines.append("No naming violations found.")
        else:
            for violation in self._violations[:limit]:
                lines.append(violation.format())
            if len(self._violations) > limit:
                lines.append(f"... and {len(self._violations) - limit} more")
        return "\n".join(lines)
