"""DocstringCoverage — analyze docstring coverage in Python projects."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class DocstringGap:
    """A function, method, or class missing a docstring."""

    path: str
    name: str
    lineno: int
    kind: str

    def format(self) -> str:
        """Return a single-line description of the gap."""
        return f"{self.path}:{self.lineno} {self.kind} {self.name} — missing docstring"


@dataclass
class DocstringStats:
    """Aggregate docstring coverage statistics."""

    total_items: int
    documented: int
    undocumented: int

    @property
    def coverage_pct(self) -> float:
        if self.total_items == 0:
            return 100.0
        return round(100.0 * self.documented / self.total_items, 1)


class DocstringCoverage:
    """Analyze docstring coverage across a Python project."""

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        include_private: bool = False,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.include_private = include_private
        self._gaps: list[DocstringGap] = []
        self._stats: DocstringStats | None = None

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _has_docstring(self, node: ast.AST) -> bool:
        body = getattr(node, "body", None)
        if not body:
            return False
        first = body[0]
        return (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
            and first.value.value.strip()
        )

    def _should_include(self, name: str) -> bool:
        if self.include_private:
            return True
        return not name.startswith("_") or name in ("__init__", "__call__")

    def _qualified_name(self, stack: list[str], name: str) -> str:
        if stack:
            return ".".join(stack + [name])
        return name

    def _analyze_file(self, path: Path) -> tuple[list[DocstringGap], int, int]:
        relative = str(path.relative_to(self.root))
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError):
            return [], 0, 0

        gaps: list[DocstringGap] = []
        documented = 0
        total = 0

        def check_item(name: str, node: ast.AST, kind: str, lineno: int) -> None:
            nonlocal documented, total
            if not self._should_include(name):
                return
            total += 1
            if self._has_docstring(node):
                documented += 1
            else:
                gaps.append(
                    DocstringGap(path=relative, name=name, lineno=lineno, kind=kind)
                )

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                check_item(node.name, node, "class", node.lineno)
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qname = self._qualified_name([node.name], child.name)
                        kind = "async method" if isinstance(child, ast.AsyncFunctionDef) else "method"
                        check_item(qname, child, kind, child.lineno)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                kind = "async function" if isinstance(node, ast.AsyncFunctionDef) else "function"
                check_item(node.name, node, kind, node.lineno)

        return gaps, documented, total

    def analyze(self) -> list[DocstringGap]:
        """Scan the project and return items missing docstrings."""
        if self._gaps and self._stats is not None:
            return self._gaps

        gaps: list[DocstringGap] = []
        documented = 0
        total = 0

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            file_gaps, file_doc, file_total = self._analyze_file(path)
            gaps.extend(file_gaps)
            documented += file_doc
            total += file_total

        self._gaps = gaps
        self._stats = DocstringStats(
            total_items=total,
            documented=documented,
            undocumented=total - documented,
        )
        return gaps

    @property
    def stats(self) -> DocstringStats:
        """Return aggregate docstring statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def coverage_pct(self) -> float:
        """Return the percentage of documented items."""
        return self.stats.coverage_pct

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Docstring coverage: {stats.coverage_pct}% "
            f"({stats.documented}/{stats.total_items} documented)",
            f"Undocumented: {stats.undocumented}",
            f"Items with gaps: {len(self._gaps)}",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing docstring gaps."""
        self.analyze()
        lines = [
            "Docstring coverage analysis:",
            self.summary(),
            "",
            "Items missing docstrings:",
        ]
        if not self._gaps:
            lines.append("All analyzed items have docstrings.")
        else:
            for gap in self._gaps[:limit]:
                lines.append(gap.format())
            if len(self._gaps) > limit:
                lines.append(f"... and {len(self._gaps) - limit} more")
        return "\n".join(lines)
