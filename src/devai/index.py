"""CodeSymbolIndex — AST-based symbol indexer for Python projects."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class SymbolInfo:
    """A symbol discovered in a Python source file."""

    name: str
    kind: str
    path: str
    lineno: int
    parent: str | None = None
    signature: str | None = None

    def qualified_name(self) -> str:
        """Return a fully qualified symbol name."""
        if self.parent:
            return f"{self.parent}.{self.name}"
        return self.name


class CodeSymbolIndex:
    """Index functions, classes, and methods in a Python project."""

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._symbols: list[SymbolInfo] = []

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _signature_for(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        args = [arg.arg for arg in node.args.args]
        return f"{node.name}({', '.join(args)})"

    def _index_file(self, path: Path) -> list[SymbolInfo]:
        relative = str(path.relative_to(self.root))
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError):
            return []

        symbols: list[SymbolInfo] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbols.append(
                    SymbolInfo(
                        name=node.name,
                        kind="function",
                        path=relative,
                        lineno=node.lineno,
                        signature=self._signature_for(node),
                    )
                )
            elif isinstance(node, ast.ClassDef):
                symbols.append(
                    SymbolInfo(
                        name=node.name,
                        kind="class",
                        path=relative,
                        lineno=node.lineno,
                    )
                )
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        symbols.append(
                            SymbolInfo(
                                name=item.name,
                                kind="method",
                                path=relative,
                                lineno=item.lineno,
                                parent=node.name,
                                signature=self._signature_for(item),
                            )
                        )
        return symbols

    def build(self) -> list[SymbolInfo]:
        """Scan the project and build the symbol index."""
        self._symbols = []
        if not self.root.exists():
            return self._symbols

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            self._symbols.extend(self._index_file(path))
        return self._symbols

    @property
    def symbols(self) -> list[SymbolInfo]:
        """Return indexed symbols, building the index on first access."""
        if not self._symbols:
            self.build()
        return list(self._symbols)

    def search(self, query: str, *, kind: str | None = None) -> list[SymbolInfo]:
        """Search symbols by name substring (case-insensitive)."""
        query_lower = query.lower()
        results = [
            s
            for s in self.symbols
            if query_lower in s.name.lower() or query_lower in s.qualified_name().lower()
        ]
        if kind:
            results = [s for s in results if s.kind == kind]
        return results

    def find(self, name: str) -> list[SymbolInfo]:
        """Find symbols by exact name."""
        return [s for s in self.symbols if s.name == name or s.qualified_name() == name]

    def summary(self) -> str:
        """Return a human-readable summary of indexed symbols."""
        symbols = self.symbols
        if not symbols:
            return f"No Python symbols found in {self.root}"

        by_kind: dict[str, int] = {}
        for symbol in symbols:
            by_kind[symbol.kind] = by_kind.get(symbol.kind, 0) + 1

        lines = [
            f"Symbol index: {self.root}",
            f"Total symbols: {len(symbols)}",
        ]
        for kind, count in sorted(by_kind.items()):
            lines.append(f"  {kind}: {count}")
        return "\n".join(lines)

    def to_context(self, query: str | None = None, max_symbols: int = 50) -> str:
        """Build LLM context from matching symbols."""
        symbols = self.search(query) if query else self.symbols
        if not symbols:
            return self.summary()

        lines = [self.summary(), "", "Symbols:"]
        for symbol in symbols[:max_symbols]:
            location = f"{symbol.path}:{symbol.lineno}"
            qualified = symbol.qualified_name()
            extra = f" — {symbol.signature}" if symbol.signature else ""
            lines.append(f"  [{symbol.kind}] {qualified} @ {location}{extra}")
        if len(symbols) > max_symbols:
            lines.append(f"  ... and {len(symbols) - max_symbols} more")
        return "\n".join(lines)
