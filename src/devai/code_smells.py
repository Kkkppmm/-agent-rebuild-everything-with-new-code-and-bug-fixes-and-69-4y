"""CodeSmellDetector — AST-based code smell detection for Python projects."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class CodeSmell:
    """A detected code smell in a Python source file."""

    path: str
    name: str
    lineno: int
    kind: str
    message: str
    severity: str = "medium"

    def format(self) -> str:
        """Return a single-line description."""
        return f"{self.path}:{self.lineno} [{self.severity}] {self.kind}: {self.name} — {self.message}"


@dataclass
class CodeSmellStats:
    """Aggregate code smell statistics."""

    total_smells: int
    by_kind: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    smell_density: float = 0.0


class _SmellVisitor(ast.NodeVisitor):
    """Walk a module AST and collect code smells."""

    def __init__(
        self,
        path: str,
        *,
        max_lines: int,
        max_params: int,
        max_nesting: int,
        max_methods: int,
    ) -> None:
        self.path = path
        self.max_lines = max_lines
        self.max_params = max_params
        self.max_nesting = max_nesting
        self.max_methods = max_methods
        self.smells: list[CodeSmell] = []
        self._class_stack: list[str] = []

    def _add(
        self,
        node: ast.AST,
        name: str,
        kind: str,
        message: str,
        severity: str = "medium",
    ) -> None:
        lineno = getattr(node, "lineno", 1)
        self.smells.append(
            CodeSmell(
                path=self.path,
                name=name,
                lineno=lineno,
                kind=kind,
                message=message,
                severity=severity,
            )
        )

    def _qualified_name(self, name: str) -> str:
        if self._class_stack:
            return f"{self._class_stack[-1]}.{name}"
        return name

    def _count_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        args = list(node.args.posonlyargs) + list(node.args.args)
        count = sum(1 for arg in args if arg.arg not in ("self", "cls"))
        if node.args.vararg:
            count += 1
        if node.args.kwarg:
            count += 1
        count += len(node.args.kwonlyargs)
        return count

    def _function_lines(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        if not node.body:
            return 1
        end = getattr(node.body[-1], "end_lineno", node.body[-1].lineno)
        return max(1, end - node.lineno + 1)

    def _max_nesting_depth(self, node: ast.AST, current: int = 0) -> int:
        nesting_nodes = (
            ast.If,
            ast.For,
            ast.AsyncFor,
            ast.While,
            ast.With,
            ast.AsyncWith,
            ast.Try,
        )
        max_depth = current
        for child in ast.iter_child_nodes(node):
            depth = current
            if isinstance(child, nesting_nodes):
                depth += 1
            max_depth = max(max_depth, self._max_nesting_depth(child, depth))
        return max_depth

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        methods = [
            child
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        if len(methods) > self.max_methods:
            self._add(
                node,
                node.name,
                "god_class",
                f"{len(methods)} methods (threshold {self.max_methods})",
                severity="high",
            )
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        name = self._qualified_name(node.name)
        lines = self._function_lines(node)
        if lines > self.max_lines:
            self._add(
                node,
                name,
                "long_function",
                f"{lines} lines (threshold {self.max_lines})",
                severity="medium",
            )

        params = self._count_params(node)
        if params > self.max_params:
            self._add(
                node,
                name,
                "too_many_params",
                f"{params} parameters (threshold {self.max_params})",
                severity="medium",
            )

        depth = self._max_nesting_depth(node)
        if depth > self.max_nesting:
            self._add(
                node,
                name,
                "deep_nesting",
                f"nesting depth {depth} (threshold {self.max_nesting})",
                severity="high",
            )

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self._add(
                node,
                "<handler>",
                "bare_except",
                "bare except clause catches all exceptions",
                severity="high",
            )
        elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
            self._add(
                node,
                "<handler>",
                "broad_except",
                f"catches {node.type.id} — prefer specific exceptions",
                severity="low",
            )
        self.generic_visit(node)


class CodeSmellDetector:
    """Detect common Python code smells using AST analysis.

    Identifies long functions, excessive parameters, deep nesting,
    bare/broad except handlers, and god classes.
    """

    def __init__(
        self,
        root: str,
        *,
        max_lines: int = 50,
        max_params: int = 5,
        max_nesting: int = 4,
        max_methods: int = 20,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.max_lines = max_lines
        self.max_params = max_params
        self.max_nesting = max_nesting
        self.max_methods = max_methods
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._smells: list[CodeSmell] = []
        self._stats: CodeSmellStats | None = None
        self._functions_analyzed = 0

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _count_functions(self, tree: ast.AST) -> int:
        count = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                count += 1
        return count

    def analyze(self) -> list[CodeSmell]:
        """Scan the project and return detected code smells."""
        if self._smells:
            return self._smells

        smells: list[CodeSmell] = []
        functions = 0

        for path in sorted(self.root.rglob("*.py")):
            if self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue

            functions += self._count_functions(tree)
            rel = str(path.relative_to(self.root))
            visitor = _SmellVisitor(
                rel,
                max_lines=self.max_lines,
                max_params=self.max_params,
                max_nesting=self.max_nesting,
                max_methods=self.max_methods,
            )
            visitor.visit(tree)
            smells.extend(visitor.smells)

        self._functions_analyzed = functions
        self._smells = smells

        by_kind: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for smell in smells:
            by_kind[smell.kind] = by_kind.get(smell.kind, 0) + 1
            by_severity[smell.severity] = by_severity.get(smell.severity, 0) + 1

        density = 0.0
        if functions:
            density = round(100.0 * len(smells) / functions, 1)

        stats = CodeSmellStats(
            total_smells=len(smells),
            by_kind=by_kind,
            by_severity=by_severity,
            smell_density=density,
        )
        self._stats = stats
        return smells

    @property
    def stats(self) -> CodeSmellStats:
        """Return aggregate smell statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_kind(self, kind: str) -> list[CodeSmell]:
        """Return smells of a specific kind."""
        return [s for s in self.analyze() if s.kind == kind]

    def by_severity(self, severity: str) -> list[CodeSmell]:
        """Return smells of a specific severity."""
        return [s for s in self.analyze() if s.severity == severity]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no smells)."""
        self.analyze()
        if self._functions_analyzed == 0:
            return 100.0
        ratio = len(self._smells) / self._functions_analyzed
        high = sum(1 for s in self._smells if s.severity == "high")
        penalty = ratio * 150.0 + high * 5.0
        return round(max(0.0, 100.0 - penalty), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Code smells: {stats.total_smells} found across {self._functions_analyzed} functions",
            f"Density: {stats.smell_density} smells per 100 functions",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_kind:
            kinds = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_kind.items()))
            lines.append(f"By kind: {kinds}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing code smells."""
        self.analyze()
        lines = [
            "Code smell analysis:",
            self.summary(),
            "",
            "Detected smells:",
        ]
        if not self._smells:
            lines.append("No code smells detected.")
        else:
            for smell in self._smells[:limit]:
                lines.append(smell.format())
            if len(self._smells) > limit:
                lines.append(f"... and {len(self._smells) - limit} more")
        return "\n".join(lines)
