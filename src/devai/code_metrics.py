"""CodeMetrics — static code metrics for Python projects."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class FunctionMetric:
    """Metrics for a single function or method."""

    path: str
    name: str
    lineno: int
    lines: int
    complexity: int

    def format(self) -> str:
        """Return a single-line description."""
        return f"{self.path}:{self.lineno} {self.name} — {self.lines} lines, complexity {self.complexity}"


@dataclass
class FileMetric:
    """Metrics for a single source file."""

    path: str
    lines_total: int
    lines_code: int
    lines_blank: int
    lines_comment: int
    functions: int
    classes: int
    max_complexity: int

    @property
    def avg_complexity(self) -> float:
        return 0.0


@dataclass
class ProjectMetrics:
    """Aggregate project-level metrics."""

    files: int
    lines_total: int
    lines_code: int
    lines_blank: int
    lines_comment: int
    functions: int
    classes: int
    avg_complexity: float
    max_complexity: int
    high_complexity_count: int
    extensions: dict[str, int] = field(default_factory=dict)


class CodeMetrics:
    """Analyze static code metrics across a Python project."""

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        complexity_threshold: int = 10,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.complexity_threshold = complexity_threshold
        self._file_metrics: list[FileMetric] = []
        self._function_metrics: list[FunctionMetric] = []
        self._project: ProjectMetrics | None = None

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _count_lines(self, source: str) -> tuple[int, int, int]:
        code = blank = comment = 0
        for line in source.splitlines():
            stripped = line.strip()
            if not stripped:
                blank += 1
            elif stripped.startswith("#"):
                comment += 1
            else:
                code += 1
        return code, blank, comment

    def _function_complexity(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    def _analyze_file(self, path: Path) -> tuple[FileMetric, list[FunctionMetric]]:
        relative = str(path.relative_to(self.root))
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError):
            return FileMetric(relative, 0, 0, 0, 0, 0, 0, 0), []

        lines = source.splitlines()
        code, blank, comment = self._count_lines(source)
        functions = 0
        classes = 0
        func_metrics: list[FunctionMetric] = []
        max_complexity = 0

        stack: list[str] = []
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                classes += 1
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        functions += 1
                        complexity = self._function_complexity(child)
                        max_complexity = max(max_complexity, complexity)
                        end = child.end_lineno or child.lineno
                        func_metrics.append(
                            FunctionMetric(
                                path=relative,
                                name=f"{node.name}.{child.name}",
                                lineno=child.lineno,
                                lines=end - child.lineno + 1,
                                complexity=complexity,
                            )
                        )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                complexity = self._function_complexity(node)
                max_complexity = max(max_complexity, complexity)
                end = node.end_lineno or node.lineno
                func_metrics.append(
                    FunctionMetric(
                        path=relative,
                        name=node.name,
                        lineno=node.lineno,
                        lines=end - node.lineno + 1,
                        complexity=complexity,
                    )
                )

        file_metric = FileMetric(
            path=relative,
            lines_total=len(lines),
            lines_code=code,
            lines_blank=blank,
            lines_comment=comment,
            functions=functions,
            classes=classes,
            max_complexity=max_complexity,
        )
        return file_metric, func_metrics

    def analyze(self) -> ProjectMetrics:
        """Scan the project and return aggregate metrics."""
        if self._project is not None:
            return self._project

        file_metrics: list[FileMetric] = []
        func_metrics: list[FunctionMetric] = []
        extensions: dict[str, int] = {}

        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue
            ext = path.suffix.lower() or "(no ext)"
            extensions[ext] = extensions.get(ext, 0) + 1
            if path.suffix != ".py":
                continue
            fm, fms = self._analyze_file(path)
            if fm.lines_total > 0 or fm.functions > 0:
                file_metrics.append(fm)
                func_metrics.extend(fms)

        self._file_metrics = file_metrics
        self._function_metrics = func_metrics

        total_lines = sum(f.lines_total for f in file_metrics)
        code_lines = sum(f.lines_code for f in file_metrics)
        blank_lines = sum(f.lines_blank for f in file_metrics)
        comment_lines = sum(f.lines_comment for f in file_metrics)
        total_functions = sum(f.functions for f in file_metrics)
        total_classes = sum(f.classes for f in file_metrics)

        complexities = [fm.complexity for fm in func_metrics]
        avg_complexity = sum(complexities) / len(complexities) if complexities else 0.0
        max_complexity = max(complexities) if complexities else 0
        high_count = sum(1 for c in complexities if c >= self.complexity_threshold)

        self._project = ProjectMetrics(
            files=len(file_metrics),
            lines_total=total_lines,
            lines_code=code_lines,
            lines_blank=blank_lines,
            lines_comment=comment_lines,
            functions=total_functions,
            classes=total_classes,
            avg_complexity=round(avg_complexity, 1),
            max_complexity=max_complexity,
            high_complexity_count=high_count,
            extensions=extensions,
        )
        return self._project

    @property
    def stats(self) -> ProjectMetrics:
        """Return aggregate project metrics."""
        return self.analyze()

    def high_complexity(self, threshold: int | None = None) -> list[FunctionMetric]:
        """Return functions exceeding the complexity threshold."""
        self.analyze()
        limit = threshold or self.complexity_threshold
        return sorted(
            [fm for fm in self._function_metrics if fm.complexity >= limit],
            key=lambda m: (-m.complexity, m.path, m.lineno),
        )

    def largest_files(self, limit: int = 10) -> list[FileMetric]:
        """Return the largest files by line count."""
        self.analyze()
        return sorted(self._file_metrics, key=lambda f: -f.lines_total)[:limit]

    def summary(self) -> str:
        """Return a human-readable summary."""
        stats = self.analyze()
        lines = [
            f"Python files: {stats.files}",
            f"Lines: {stats.lines_total} total ({stats.lines_code} code, "
            f"{stats.lines_comment} comment, {stats.lines_blank} blank)",
            f"Functions: {stats.functions}, classes: {stats.classes}",
            f"Complexity: avg {stats.avg_complexity}, max {stats.max_complexity}, "
            f"{stats.high_complexity_count} functions >= {self.complexity_threshold}",
        ]
        if stats.extensions:
            ext_summary = ", ".join(f"{k}: {v}" for k, v in sorted(stats.extensions.items()))
            lines.append(f"All files by extension: {ext_summary}")
        return "\n".join(lines)

    def to_context(self, limit: int = 20) -> str:
        """Build LLM-ready context describing project metrics."""
        self.analyze()
        lines = [
            "Static code metrics analysis:",
            self.summary(),
            "",
            "High-complexity functions:",
        ]
        high = self.high_complexity()
        if not high:
            lines.append("No functions exceed the complexity threshold.")
        else:
            for fm in high[:limit]:
                lines.append(fm.format())
            if len(high) > limit:
                lines.append(f"... and {len(high) - limit} more")
        lines.append("")
        lines.append("Largest files:")
        for fm in self.largest_files(5):
            lines.append(
                f"{fm.path}: {fm.lines_total} lines, {fm.functions} functions, "
                f"max complexity {fm.max_complexity}"
            )
        return "\n".join(lines)
