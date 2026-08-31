"""MagicNumberDetector — find unexplained numeric literals in Python code."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SCREAMING_SNAKE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_ALLOWED_INTS = frozenset({0, 1, -1, 2})
_ALLOWED_FLOATS = frozenset({0.0, 1.0, -1.0, 2.0})


@dataclass
class MagicNumber:
    """An unexplained numeric literal that should likely be a named constant."""

    path: str
    value: str
    lineno: int
    col_offset: int
    context: str
    message: str

    def format(self) -> str:
        """Return a single-line description."""
        return (
            f"{self.path}:{self.lineno}:{self.col_offset} "
            f"[{self.context}] {self.value} — {self.message}"
        )


@dataclass
class MagicNumberStats:
    """Aggregate magic-number statistics."""

    total_findings: int
    by_context: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_magic_number(value: int | float) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value not in _ALLOWED_INTS
    if isinstance(value, float):
        return value not in _ALLOWED_FLOATS
    return False


def _format_value(value: int | float) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


class _MagicNumberVisitor(ast.NodeVisitor):
    """Walk a module AST and collect magic numeric literals."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[MagicNumber] = []
        self._module_constants: set[str] = set()
        self._class_stack: list[str] = []
        self._in_constant_assign = False

    def _add(self, node: ast.Constant, context: str, message: str) -> None:
        value = node.value
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return
        if not _is_magic_number(value):
            return
        self.findings.append(
            MagicNumber(
                path=self.path,
                value=_format_value(value),
                lineno=getattr(node, "lineno", 1),
                col_offset=getattr(node, "col_offset", 0),
                context=context,
                message=message,
            )
        )

    def _visit_numeric(self, node: ast.AST, context: str) -> None:
        if isinstance(node, ast.Constant):
            self._add(node, context, "consider extracting to a named constant")

    def visit_Assign(self, node: ast.Assign) -> None:
        is_module_constant = not self._class_stack
        for target in node.targets:
            if isinstance(target, ast.Name) and is_module_constant:
                if _SCREAMING_SNAKE.match(target.id):
                    self._module_constants.add(target.id)
                    prev = self._in_constant_assign
                    self._in_constant_assign = True
                    self.visit(node.value)
                    self._in_constant_assign = prev
                    self.generic_visit(node)
                    return
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        self._visit_numeric(node.left, "comparison")
        for comparator in node.comparators:
            self._visit_numeric(comparator, "comparison")
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if not self._in_constant_assign:
            self._visit_numeric(node.left, "arithmetic")
            self._visit_numeric(node.right, "arithmetic")
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, (ast.UAdd, ast.USub)):
            self._visit_numeric(node.operand, "arithmetic")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        for arg in node.args:
            self._visit_numeric(arg, "argument")
        for keyword in node.keywords:
            self._visit_numeric(keyword.value, "argument")
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self._visit_numeric(node.value, "return")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        slice_node = node.slice
        if isinstance(slice_node, ast.Constant):
            self._visit_numeric(slice_node, "index")
        elif isinstance(slice_node, ast.Tuple):
            for elt in slice_node.elts:
                self._visit_numeric(elt, "index")
        elif isinstance(slice_node, ast.Slice):
            for part in (slice_node.lower, slice_node.upper, slice_node.step):
                if part is not None:
                    self._visit_numeric(part, "index")
        self.generic_visit(node)

    def visit_List(self, node: ast.List) -> None:
        if not self._in_constant_assign:
            for elt in node.elts:
                self._visit_numeric(elt, "collection")
        self.generic_visit(node)

    def visit_Tuple(self, node: ast.Tuple) -> None:
        if not self._in_constant_assign:
            for elt in node.elts:
                self._visit_numeric(elt, "collection")
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        if not self._in_constant_assign:
            for key in node.keys:
                if key is not None:
                    self._visit_numeric(key, "collection")
            for value in node.values:
                self._visit_numeric(value, "collection")
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for default in node.args.defaults:
            self._visit_numeric(default, "default")
        for default in node.args.kw_defaults:
            if default is not None:
                self._visit_numeric(default, "default")
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        for default in node.args.defaults:
            self._visit_numeric(default, "default")
        for default in node.args.kw_defaults:
            if default is not None:
                self._visit_numeric(default, "default")
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self._visit_numeric(node.test, "condition")
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self._visit_numeric(node.test, "condition")
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name):
            if node.iter.func.id == "range" and len(node.iter.args) == 1:
                self.generic_visit(node)
                return
        self.generic_visit(node)


class MagicNumberDetector:
    """Detect unexplained numeric literals that should be named constants.

    Flags inline integers and floats outside common trivial values (0, 1, -1, 2)
    and skips module-level ``SCREAMING_SNAKE_CASE`` constant definitions.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[MagicNumber] = []
        self._stats: MagicNumberStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[MagicNumber]:
        """Analyze the project and return magic number findings."""
        if self._findings:
            return self._findings

        findings: list[MagicNumber] = []
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
            visitor = _MagicNumberVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_context: dict[str, int] = {}
        for finding in findings:
            by_context[finding.context] = by_context.get(finding.context, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = MagicNumberStats(
            total_findings=len(findings),
            by_context=by_context,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> MagicNumberStats:
        """Return aggregate magic-number statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_context(self, context: str) -> list[MagicNumber]:
        """Return findings for a specific context (comparison, argument, etc.)."""
        return [f for f in self.analyze() if f.context == context]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no magic numbers)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        ratio = len(self._findings) / self._files_scanned
        return round(max(0.0, 100.0 - ratio * 50.0), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Magic numbers: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_context:
            contexts = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_context.items()))
            lines.append(f"By context: {contexts}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing magic number findings."""
        self.analyze()
        lines = [
            "Magic number analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No magic numbers found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
