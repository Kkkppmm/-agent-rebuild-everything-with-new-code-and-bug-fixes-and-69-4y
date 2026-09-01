"""TypingCoverage — analyze type hint coverage in Python projects."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class TypingGap:
    """A function or method missing type annotations."""

    path: str
    name: str
    lineno: int
    missing: list[str]

    def format(self) -> str:
        """Return a single-line description of the gap."""
        parts = ", ".join(self.missing)
        return f"{self.path}:{self.lineno} {self.name} — missing {parts}"


@dataclass
class TypingStats:
    """Aggregate typing coverage statistics."""

    total_functions: int
    fully_typed: int
    partially_typed: int
    untyped: int

    @property
    def coverage_pct(self) -> float:
        if self.total_functions == 0:
            return 100.0
        return round(100.0 * self.fully_typed / self.total_functions, 1)


class TypingCoverage:
    """Analyze type hint coverage across a Python project."""

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._gaps: list[TypingGap] = []
        self._stats: TypingStats | None = None

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _check_args(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        missing: list[str] = []
        args = list(node.args.posonlyargs) + list(node.args.args)
        if node.args.vararg and node.args.vararg.annotation is None:
            missing.append(f"*{node.args.vararg.arg}")
        for arg in args:
            if arg.arg in ("self", "cls"):
                continue
            if arg.annotation is None:
                missing.append(arg.arg)
        if node.args.kwarg and node.args.kwarg.annotation is None:
            missing.append(f"**{node.args.kwarg.arg}")
        for arg in node.args.kwonlyargs:
            if arg.annotation is None:
                missing.append(arg.arg)
        if node.returns is None:
            missing.append("return")
        return missing

    def _qualified_name(self, stack: list[str], name: str) -> str:
        if stack:
            return ".".join(stack + [name])
        return name

    def _analyze_file(self, path: Path) -> list[TypingGap]:
        relative = str(path.relative_to(self.root))
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError):
            return []

        gaps: list[TypingGap] = []
        stack: list[str] = []

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        missing = self._check_args(child)
                        if missing:
                            gaps.append(
                                TypingGap(
                                    path=relative,
                                    name=self._qualified_name([node.name], child.name),
                                    lineno=child.lineno,
                                    missing=missing,
                                )
                            )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                missing = self._check_args(node)
                if missing:
                    gaps.append(
                        TypingGap(
                            path=relative,
                            name=node.name,
                            lineno=node.lineno,
                            missing=missing,
                        )
                    )
        return gaps

    def analyze(self) -> list[TypingGap]:
        """Scan the project and return functions missing type hints."""
        if self._gaps and self._stats is not None:
            return self._gaps

        gaps: list[TypingGap] = []
        total = 0
        fully = 0
        partial = 0

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            file_gaps = self._analyze_file(path)
            gaps.extend(file_gaps)

            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except (OSError, SyntaxError):
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name.startswith("_") and node.name != "__init__":
                        continue
                    total += 1
                    missing = self._check_args(node)
                    if not missing:
                        fully += 1
                    elif len(missing) == 1 and missing[0] == "return":
                        partial += 1

        untyped = total - fully - partial
        self._gaps = gaps
        self._stats = TypingStats(
            total_functions=total,
            fully_typed=fully,
            partially_typed=partial,
            untyped=untyped,
        )
        return gaps

    @property
    def stats(self) -> TypingStats:
        """Return aggregate typing statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def coverage_pct(self) -> float:
        """Return the percentage of fully typed functions."""
        return self.stats.coverage_pct

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Typing coverage: {stats.coverage_pct}% ({stats.fully_typed}/{stats.total_functions} fully typed)",
            f"Partially typed: {stats.partially_typed}, untyped: {stats.untyped}",
            f"Functions with gaps: {len(self._gaps)}",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing typing gaps."""
        self.analyze()
        lines = [
            "Type hint coverage analysis:",
            self.summary(),
            "",
            "Functions missing annotations:",
        ]
        if not self._gaps:
            lines.append("All analyzed functions are fully typed.")
        else:
            for gap in self._gaps[:limit]:
                lines.append(gap.format())
            if len(self._gaps) > limit:
                lines.append(f"... and {len(self._gaps) - limit} more")
        return "\n".join(lines)
