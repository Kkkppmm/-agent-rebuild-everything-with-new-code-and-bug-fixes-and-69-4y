"""ExceptionHierarchyAnalyzer — map custom exceptions and risky handlers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class ExceptionInfo:
    """A custom exception class found in the project."""

    path: str
    name: str
    lineno: int
    bases: list[str] = field(default_factory=list)

    def format(self) -> str:
        """Return a single-line description."""
        base_str = ", ".join(self.bases) if self.bases else "Exception"
        return f"{self.path}:{self.lineno} class {self.name}({base_str})"


@dataclass
class BroadExceptHandler:
    """A broad or bare except handler."""

    path: str
    lineno: int
    handler_type: str
    caught: str

    def format(self) -> str:
        """Return a single-line description."""
        return f"{self.path}:{self.lineno} {self.handler_type}: {self.caught}"


@dataclass
class ExceptionStats:
    """Aggregate exception analysis statistics."""

    custom_exceptions: int
    broad_handlers: int
    bare_except: int
    hierarchy_depth: int = 0


class ExceptionHierarchyAnalyzer:
    """Analyze custom exception classes and risky exception handlers.

    Scans Python source for:
    - Custom ``Exception`` subclasses and their inheritance chains
    - Bare ``except:`` handlers
    - Overly broad ``except Exception`` handlers
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._exceptions: list[ExceptionInfo] = []
        self._broad_handlers: list[BroadExceptHandler] = []
        self._stats: ExceptionStats | None = None

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix.lower() != ".py"

    def _base_names(self, node: ast.ClassDef) -> list[str]:
        names: list[str] = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                names.append(base.id)
            elif isinstance(base, ast.Attribute):
                names.append(base.attr)
        return names

    def _is_exception_class(self, node: ast.ClassDef) -> bool:
        bases = self._base_names(node)
        if not bases:
            return False
        for base in bases:
            if base in ("Exception", "BaseException") or base.endswith("Error"):
                return True
        return False

    def _analyze_file(self, rel: str, source: str) -> None:
        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and self._is_exception_class(node):
                self._exceptions.append(
                    ExceptionInfo(
                        path=rel,
                        name=node.name,
                        lineno=node.lineno,
                        bases=self._base_names(node),
                    )
                )
            elif isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    self._broad_handlers.append(
                        BroadExceptHandler(
                            path=rel,
                            lineno=node.lineno,
                            handler_type="bare except",
                            caught="all",
                        )
                    )
                elif isinstance(node.type, ast.Name) and node.type.id in (
                    "Exception",
                    "BaseException",
                ):
                    self._broad_handlers.append(
                        BroadExceptHandler(
                            path=rel,
                            lineno=node.lineno,
                            handler_type="broad except",
                            caught=node.type.id,
                        )
                    )

    def analyze(self) -> list[ExceptionInfo]:
        """Scan the project and return custom exception classes."""
        if self._exceptions:
            return list(self._exceptions)

        if not self.root.exists():
            return []

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            rel = str(path.relative_to(self.root))
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self._analyze_file(rel, source)

        self._stats = ExceptionStats(
            custom_exceptions=len(self._exceptions),
            broad_handlers=len(self._broad_handlers),
            bare_except=sum(1 for h in self._broad_handlers if h.handler_type == "bare except"),
            hierarchy_depth=self._max_hierarchy_depth(),
        )
        return list(self._exceptions)

    def _max_hierarchy_depth(self) -> int:
        if not self._exceptions:
            return 0
        by_name = {e.name: e for e in self._exceptions}
        max_depth = 0
        for exc in self._exceptions:
            depth = 1
            current = exc
            seen: set[str] = set()
            while current.bases:
                parent_name = current.bases[0]
                if parent_name in seen:
                    break
                seen.add(parent_name)
                parent = by_name.get(parent_name)
                if parent is None:
                    break
                depth += 1
                current = parent
            max_depth = max(max_depth, depth)
        return max_depth

    @property
    def exceptions(self) -> list[ExceptionInfo]:
        """Return custom exceptions (runs analysis on first access)."""
        if not self._exceptions:
            self.analyze()
        return list(self._exceptions)

    @property
    def broad_handlers(self) -> list[BroadExceptHandler]:
        """Return broad or bare except handlers."""
        if not self._exceptions and not self._broad_handlers:
            self.analyze()
        return list(self._broad_handlers)

    @property
    def stats(self) -> ExceptionStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats

    def health_score(self) -> float:
        """Return a 0–100 health score (higher is better)."""
        stats = self.stats
        penalty = stats.bare_except * 20.0 + (stats.broad_handlers - stats.bare_except) * 8.0
        return max(0.0, round(100.0 - penalty, 1))

    def summary(self) -> str:
        """Return a human-readable summary."""
        stats = self.stats
        lines = [
            f"Exception analysis: {self.root}",
            f"Custom exceptions: {stats.custom_exceptions}",
            f"Broad/bare handlers: {stats.broad_handlers} ({stats.bare_except} bare)",
            f"Max hierarchy depth: {stats.hierarchy_depth}",
            f"Health score: {self.health_score():.0f}/100",
        ]
        return "\n".join(lines)

    def to_context(self, max_items: int = 30) -> str:
        """Build LLM-ready context describing exception usage."""
        lines = [self.summary(), ""]
        if self.exceptions:
            lines.append("Custom exceptions:")
            for exc in self.exceptions[:max_items]:
                lines.append(f"  {exc.format()}")
            if len(self.exceptions) > max_items:
                lines.append(f"  ... and {len(self.exceptions) - max_items} more")
        if self.broad_handlers:
            lines.append("")
            lines.append("Risky handlers:")
            for handler in self.broad_handlers[:max_items]:
                lines.append(f"  {handler.format()}")
            if len(self.broad_handlers) > max_items:
                lines.append(f"  ... and {len(self.broad_handlers) - max_items} more")
        return "\n".join(lines)
