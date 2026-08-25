"""CodeMetrics — static code analysis for Python projects."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class FunctionMetrics:
    """Metrics for a single function or method."""

    name: str
    path: str
    lineno: int
    complexity: int
    params: int
    lines: int
    is_async: bool = False

    def format(self) -> str:
        """Return a single-line description."""
        kind = "async " if self.is_async else ""
        return (
            f"{self.path}:{self.lineno} {kind}{self.name}() "
            f"complexity={self.complexity} params={self.params} lines={self.lines}"
        )


@dataclass
class FileMetrics:
    """Metrics for a single Python file."""

    path: str
    loc: int
    sloc: int
    blank_lines: int
    comment_lines: int
    functions: int
    classes: int
    max_complexity: int
    avg_complexity: float

    def format(self) -> str:
        """Return a single-line summary."""
        return (
            f"{self.path}: {self.sloc} sloc, {self.functions} fn, "
            f"{self.classes} cls, max_complexity={self.max_complexity}"
        )


@dataclass
class ProjectMetrics:
    """Aggregate metrics across a project."""

    files: int
    total_loc: int
    total_sloc: int
    total_functions: int
    total_classes: int
    avg_complexity: float
    max_complexity: int
    high_complexity_count: int = 0

    @property
    def avg_sloc_per_file(self) -> float:
        if self.files == 0:
            return 0.0
        return round(self.total_sloc / self.files, 1)


class _ComplexityVisitor(ast.NodeVisitor):
    """Count cyclomatic complexity for a function body."""

    def __init__(self) -> None:
        self.complexity = 1

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.complexity += max(0, len(node.values) - 1)
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self.complexity += 1
        self.generic_visit(node)


def _count_lines(source: str) -> tuple[int, int, int]:
    """Return (loc, sloc, blank, comment) line counts."""
    loc = 0
    sloc = 0
    blank = 0
    comment = 0
    for line in source.splitlines():
        loc += 1
        stripped = line.strip()
        if not stripped:
            blank += 1
        elif stripped.startswith("#"):
            comment += 1
        else:
            sloc += 1
    return loc, sloc, blank, comment


def _param_count(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    args = list(node.args.posonlyargs) + list(node.args.args)
    count = len([a for a in args if a.arg not in ("self", "cls")])
    count += len(node.args.kwonlyargs)
    if node.args.vararg:
        count += 1
    if node.args.kwarg:
        count += 1
    return count


def _function_lines(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    if hasattr(node, "end_lineno") and node.end_lineno is not None:
        return node.end_lineno - node.lineno + 1
    return 1


class CodeMetrics:
    """Analyze static code metrics across a Python project.

    Computes lines of code, function counts, and cyclomatic complexity
    without calling an LLM — useful for CI gates and code health dashboards.
    """

    DEFAULT_COMPLEXITY_THRESHOLD = 10

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        complexity_threshold: int = DEFAULT_COMPLEXITY_THRESHOLD,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.complexity_threshold = complexity_threshold
        self._file_metrics: list[FileMetrics] = []
        self._function_metrics: list[FunctionMetrics] = []
        self._project: ProjectMetrics | None = None

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _qualified_name(self, stack: list[str], name: str) -> str:
        if stack:
            return ".".join(stack + [name])
        return name

    def _analyze_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        relative: str,
        stack: list[str],
    ) -> FunctionMetrics:
        visitor = _ComplexityVisitor()
        for child in ast.walk(node):
            if child is not node and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            visitor.visit(child)
        return FunctionMetrics(
            name=self._qualified_name(stack, node.name),
            path=relative,
            lineno=node.lineno,
            complexity=visitor.complexity,
            params=_param_count(node),
            lines=_function_lines(node),
            is_async=isinstance(node, ast.AsyncFunctionDef),
        )

    def _analyze_file(self, path: Path) -> tuple[FileMetrics, list[FunctionMetrics]]:
        relative = str(path.relative_to(self.root))
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError):
            return FileMetrics(relative, 0, 0, 0, 0, 0, 0, 0, 0.0), []

        loc, sloc, blank, comment = _count_lines(source)
        functions: list[FunctionMetrics] = []
        classes = 0

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                classes += 1
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        functions.append(self._analyze_function(child, relative, [node.name]))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(self._analyze_function(node, relative, []))

        complexities = [f.complexity for f in functions]
        max_cx = max(complexities) if complexities else 0
        avg_cx = round(sum(complexities) / len(complexities), 1) if complexities else 0.0

        file_metrics = FileMetrics(
            path=relative,
            loc=loc,
            sloc=sloc,
            blank_lines=blank,
            comment_lines=comment,
            functions=len(functions),
            classes=classes,
            max_complexity=max_cx,
            avg_complexity=avg_cx,
        )
        return file_metrics, functions

    def analyze(self) -> list[FileMetrics]:
        """Scan the project and return per-file metrics."""
        if self._file_metrics:
            return self._file_metrics

        file_metrics: list[FileMetrics] = []
        function_metrics: list[FunctionMetrics] = []

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            fm, fns = self._analyze_file(path)
            file_metrics.append(fm)
            function_metrics.extend(fns)

        self._file_metrics = file_metrics
        self._function_metrics = function_metrics
        self._project = self._build_project_metrics(file_metrics, function_metrics)
        return file_metrics

    def _build_project_metrics(
        self,
        files: list[FileMetrics],
        functions: list[FunctionMetrics],
    ) -> ProjectMetrics:
        complexities = [f.complexity for f in functions]
        high = sum(1 for c in complexities if c >= self.complexity_threshold)
        return ProjectMetrics(
            files=len(files),
            total_loc=sum(f.loc for f in files),
            total_sloc=sum(f.sloc for f in files),
            total_functions=sum(f.functions for f in files),
            total_classes=sum(f.classes for f in files),
            avg_complexity=round(sum(complexities) / len(complexities), 1) if complexities else 0.0,
            max_complexity=max(complexities) if complexities else 0,
            high_complexity_count=high,
        )

    @property
    def functions(self) -> list[FunctionMetrics]:
        """Return per-function metrics (call :meth:`analyze` first)."""
        if not self._function_metrics:
            self.analyze()
        return self._function_metrics

    @property
    def project(self) -> ProjectMetrics:
        """Return aggregate project metrics."""
        if self._project is None:
            self.analyze()
        return self._project  # type: ignore[return-value]

    def top_complex(self, limit: int = 10) -> list[FunctionMetrics]:
        """Return the most complex functions, highest first."""
        return sorted(self.functions, key=lambda f: f.complexity, reverse=True)[:limit]

    def high_complexity(self) -> list[FunctionMetrics]:
        """Return functions at or above the complexity threshold."""
        return [f for f in self.functions if f.complexity >= self.complexity_threshold]

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        p = self.project
        lines = [
            f"Files: {p.files}, SLOC: {p.total_sloc}, LOC: {p.total_loc}",
            f"Functions: {p.total_functions}, Classes: {p.total_classes}",
            f"Avg complexity: {p.avg_complexity}, Max: {p.max_complexity}",
            f"High complexity (≥{self.complexity_threshold}): {p.high_complexity_count}",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 20) -> str:
        """Build LLM-ready context describing code metrics."""
        self.analyze()
        lines = [
            "Code metrics analysis:",
            self.summary(),
            "",
            "Most complex functions:",
        ]
        top = self.top_complex(limit)
        if not top:
            lines.append("No functions found.")
        else:
            for fn in top:
                lines.append(fn.format())
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Export metrics as a JSON-serializable dict."""
        self.analyze()
        p = self.project
        return {
            "project": {
                "files": p.files,
                "total_loc": p.total_loc,
                "total_sloc": p.total_sloc,
                "total_functions": p.total_functions,
                "total_classes": p.total_classes,
                "avg_complexity": p.avg_complexity,
                "max_complexity": p.max_complexity,
                "high_complexity_count": p.high_complexity_count,
                "avg_sloc_per_file": p.avg_sloc_per_file,
            },
            "files": [
                {
                    "path": f.path,
                    "sloc": f.sloc,
                    "functions": f.functions,
                    "classes": f.classes,
                    "max_complexity": f.max_complexity,
                }
                for f in self._file_metrics
            ],
            "top_complex": [
                {
                    "name": f.name,
                    "path": f.path,
                    "lineno": f.lineno,
                    "complexity": f.complexity,
                }
                for f in self.top_complex(10)
            ],
        }
