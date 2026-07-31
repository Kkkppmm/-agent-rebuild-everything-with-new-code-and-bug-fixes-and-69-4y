"""DeadCodeAnalyzer — find potentially unused Python functions and classes."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class DeadSymbol:
    """A potentially unused top-level symbol."""

    path: str
    name: str
    kind: str
    lineno: int

    def format(self) -> str:
        """Return a single-line description."""
        return f"{self.path}:{self.lineno} {self.kind} {self.name}"


@dataclass
class DeadCodeStats:
    """Aggregate dead-code statistics."""

    total_symbols: int
    dead_symbols: int
    by_kind: dict[str, int] = field(default_factory=dict)
    dead_ratio: float = 0.0


class DeadCodeAnalyzer:
    """Find potentially unused top-level Python functions and classes.

    Uses AST parsing to collect public definitions, then checks whether each
    symbol name appears elsewhere in the project (excluding its definition site).
  """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        entry_points: tuple[str, ...] = ("main", "__main__"),
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.entry_points = entry_points
        self._dead: list[DeadSymbol] = []
        self._all_definitions: list[DeadSymbol] = []
        self._stats: DeadCodeStats | None = None
        self._file_contents: dict[str, str] = {}

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix.lower() != ".py"

    def _collect_files(self) -> list[Path]:
        return [
            p
            for p in sorted(self.root.rglob("*.py"))
            if p.is_file() and not self._should_skip(p)
        ]

    def _load_contents(self, files: list[Path]) -> None:
        self._file_contents = {}
        for path in files:
            rel = str(path.relative_to(self.root))
            try:
                self._file_contents[rel] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

    def _collect_definitions(self) -> list[DeadSymbol]:
        definitions: list[DeadSymbol] = []
        for rel, source in self._file_contents.items():
            try:
                tree = ast.parse(source, filename=rel)
            except SyntaxError:
                continue
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, ast.FunctionDef):
                    if not node.name.startswith("_"):
                        definitions.append(
                            DeadSymbol(rel, node.name, "function", node.lineno)
                        )
                elif isinstance(node, ast.AsyncFunctionDef):
                    if not node.name.startswith("_"):
                        definitions.append(
                            DeadSymbol(rel, node.name, "async_function", node.lineno)
                        )
                elif isinstance(node, ast.ClassDef):
                    if not node.name.startswith("_"):
                        definitions.append(
                            DeadSymbol(rel, node.name, "class", node.lineno)
                        )
        return definitions

    def _is_referenced(self, symbol: DeadSymbol) -> bool:
        if symbol.name in self.entry_points:
            return True

        pattern = re.compile(rf"\b{re.escape(symbol.name)}\b")
        for rel, source in self._file_contents.items():
            for lineno, line in enumerate(source.splitlines(), start=1):
                if rel == symbol.path and lineno == symbol.lineno:
                    continue
                if pattern.search(line):
                    return True
        return False

    def analyze(self) -> list[DeadSymbol]:
        """Scan the project and return potentially dead symbols."""
        if self._dead:
            return self._dead

        files = self._collect_files()
        self._load_contents(files)
        self._all_definitions = self._collect_definitions()

        dead: list[DeadSymbol] = []
        for symbol in self._all_definitions:
            if not self._is_referenced(symbol):
                dead.append(symbol)

        dead.sort(key=lambda s: (s.path, s.lineno))
        self._dead = dead

        by_kind: dict[str, int] = {}
        for symbol in dead:
            by_kind[symbol.kind] = by_kind.get(symbol.kind, 0) + 1

        ratio = 0.0
        if self._all_definitions:
            ratio = round(100.0 * len(dead) / len(self._all_definitions), 1)

        self._stats = DeadCodeStats(
            total_symbols=len(self._all_definitions),
            dead_symbols=len(dead),
            by_kind=by_kind,
            dead_ratio=ratio,
        )
        return dead

    @property
    def stats(self) -> DeadCodeStats:
        """Return aggregate dead-code statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no dead code)."""
        self.analyze()
        if not self._all_definitions:
            return 100.0
        ratio = self.stats.dead_ratio
        return round(max(0.0, 100.0 - ratio * 1.5), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Dead code: {stats.dead_symbols}/{stats.total_symbols} "
            f"potentially unused symbols ({stats.dead_ratio}%)",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_kind:
            kinds = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_kind.items()))
            lines.append(f"By kind: {kinds}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing dead code."""
        self.analyze()
        lines = [
            "Dead code analysis:",
            self.summary(),
            "",
            "Potentially unused symbols:",
        ]
        if not self._dead:
            lines.append("No potentially dead symbols found.")
        else:
            for symbol in self._dead[:limit]:
                lines.append(f"  - {symbol.format()}")
            if len(self._dead) > limit:
                lines.append(f"... and {len(self._dead) - limit} more")
        return "\n".join(lines)
