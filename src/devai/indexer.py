"""AST-based code symbol indexing for Python projects."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class CodeSymbol:
    """A symbol discovered in source code."""

    name: str
    kind: str
    path: str
    line: int
    parent: str | None = None
    signature: str | None = None

    def display(self) -> str:
        """Human-readable symbol label."""
        prefix = f"{self.parent}." if self.parent else ""
        sig = f" {self.signature}" if self.signature else ""
        return f"{prefix}{self.name}{sig} ({self.kind}) @ {self.path}:{self.line}"


@dataclass
class CodeIndexer:
    """Index functions, classes, and methods from Python source files."""

    root: str
    symbols: list[CodeSymbol] = field(default_factory=list)

    def index_file(self, path: str | Path, *, relative: bool = True) -> list[CodeSymbol]:
        """Parse a single Python file and append discovered symbols."""
        file_path = Path(path)
        if not file_path.exists():
            return []

        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError):
            return []

        if relative:
            try:
                rel = str(file_path.relative_to(Path(self.root)))
            except ValueError:
                rel = str(file_path)
        else:
            rel = str(file_path)

        found: list[CodeSymbol] = []
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                found.append(
                    CodeSymbol(
                        name=node.name,
                        kind="class",
                        path=rel,
                        line=node.lineno,
                    )
                )
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        found.append(
                            CodeSymbol(
                                name=child.name,
                                kind="method",
                                path=rel,
                                line=child.lineno,
                                parent=node.name,
                                signature=_function_signature(child),
                            )
                        )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.append(
                    CodeSymbol(
                        name=node.name,
                        kind="function",
                        path=rel,
                        line=node.lineno,
                        signature=_function_signature(node),
                    )
                )

        self.symbols.extend(found)
        return found

    def index_directory(
        self,
        pattern: str = "*.py",
        *,
        ignore_dirs: set[str] | None = None,
    ) -> list[CodeSymbol]:
        """Walk the project root and index matching Python files."""
        ignore = ignore_dirs or {".git", "__pycache__", ".venv", "venv", "node_modules"}
        root = Path(self.root)
        if not root.exists():
            return []

        all_found: list[CodeSymbol] = []
        for path in sorted(root.rglob(pattern)):
            if not path.is_file() or any(part in ignore for part in path.parts):
                continue
            all_found.extend(self.index_file(path))
        return all_found

    def search(self, query: str, *, limit: int = 20) -> list[CodeSymbol]:
        """Find symbols whose name contains the query (case-insensitive)."""
        needle = query.lower()
        matches = [s for s in self.symbols if needle in s.name.lower()]
        return matches[:limit]

    def by_path(self, path: str) -> list[CodeSymbol]:
        """Return all symbols in a given file path."""
        return [s for s in self.symbols if s.path == path]

    def to_context(self, *, max_symbols: int = 50) -> str:
        """Format indexed symbols as LLM context."""
        if not self.symbols:
            return "No symbols indexed."

        lines = [f"Code symbols ({len(self.symbols)} total):", ""]
        for symbol in self.symbols[:max_symbols]:
            lines.append(symbol.display())
        if len(self.symbols) > max_symbols:
            lines.append(f"... and {len(self.symbols) - max_symbols} more")
        return "\n".join(lines)

    def clear(self) -> None:
        """Remove all indexed symbols."""
        self.symbols.clear()


def _function_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = [arg.arg for arg in node.args.args]
    return f"({', '.join(args)})"

