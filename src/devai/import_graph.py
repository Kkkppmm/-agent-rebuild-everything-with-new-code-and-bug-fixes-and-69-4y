"""ImportGraph — Python import dependency analysis and circular import detection."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ImportEdge:
    """A single import relationship between two modules."""

    source: str
    target: str
    lineno: int
    import_name: str


@dataclass
class CircularImport:
    """A detected circular import chain."""

    chain: list[str]

    def __str__(self) -> str:
        return " -> ".join(self.chain)


@dataclass
class ImportGraph:
    """Analyze Python import dependencies across a project directory.

    ImportGraph scans Python files, builds a dependency graph, and detects
  circular imports — a common source of runtime errors in larger projects.
    """

    root: Path
    _edges: list[ImportEdge] = field(default_factory=list, init=False, repr=False)
    _graph: dict[str, set[str]] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()

    def scan(self, *, exclude: frozenset[str] = frozenset({"__pycache__", ".git", ".venv", "venv"})) -> list[ImportEdge]:
        """Scan the project and collect all import edges."""
        self._edges.clear()
        self._graph.clear()

        if not self.root.is_dir():
            raise FileNotFoundError(f"Project root not found: {self.root}")

        for path in sorted(self.root.rglob("*.py")):
            if any(part in exclude for part in path.parts):
                continue
            module = self._module_name(path)
            imports = self._extract_imports(path)
            self._graph.setdefault(module, set())
            for imp, lineno in imports:
                self._edges.append(ImportEdge(source=module, target=imp, lineno=lineno, import_name=imp))
                self._graph[module].add(imp)

        return list(self._edges)

    def find_cycles(self) -> list[CircularImport]:
        """Detect circular import chains in the scanned graph."""
        if not self._graph:
            self.scan()

        cycles: list[CircularImport] = []
        seen_cycles: set[frozenset[str]] = set()

        def dfs(node: str, path: list[str], visited: set[str]) -> None:
            if node in visited:
                idx = path.index(node)
                chain = path[idx:] + [node]
                key = frozenset(chain)
                if key not in seen_cycles and len(chain) > 1:
                    seen_cycles.add(key)
                    cycles.append(CircularImport(chain=chain))
                return
            if node not in self._graph:
                return
            visited.add(node)
            path.append(node)
            for neighbor in sorted(self._graph[node]):
                dfs(neighbor, path, visited)
            path.pop()
            visited.discard(node)

        for module in sorted(self._graph):
            dfs(module, [], set())

        return cycles

    def dependencies(self, module: str) -> list[str]:
        """Return direct import targets for a module."""
        if not self._graph:
            self.scan()
        return sorted(self._graph.get(module, set()))

    def dependents(self, module: str) -> list[str]:
        """Return modules that import the given module."""
        if not self._graph:
            self.scan()
        return sorted(m for m, deps in self._graph.items() if module in deps)

    def summary(self) -> dict[str, int | list[str]]:
        """Return a summary of the import graph."""
        if not self._graph:
            self.scan()
        cycles = self.find_cycles()
        return {
            "modules": len(self._graph),
            "edges": len(self._edges),
            "circular_imports": len(cycles),
            "cycle_chains": [str(c) for c in cycles],
        }

    def _module_name(self, path: Path) -> str:
        try:
            rel = path.relative_to(self.root)
        except ValueError:
            return path.stem
        parts = list(rel.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1].replace(".py", "")
        return ".".join(parts) if parts else path.stem

    def _extract_imports(self, path: Path) -> list[tuple[str, int]]:
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            return []

        imports: list[tuple[str, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append((alias.name.split(".")[0], node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append((node.module.split(".")[0], node.lineno))
        return imports
