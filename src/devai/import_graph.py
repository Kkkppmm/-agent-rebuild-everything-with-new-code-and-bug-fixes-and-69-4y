"""ImportGraph — Python import dependency analyzer for projects."""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class ImportEdge:
    """A directed import relationship between two modules."""

    source: str
    target: str
    lineno: int
    import_name: str


class ImportGraph:
    """Build and analyze Python import dependencies in a project."""

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._edges: list[ImportEdge] = []
        self._adjacency: dict[str, set[str]] = defaultdict(set)

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _module_name(self, path: Path) -> str:
        relative = path.relative_to(self.root)
        parts = list(relative.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts) if parts else relative.stem

    def _resolve_target(self, module: str, level: int, current_module: str) -> str:
        if level > 0:
            parent_parts = current_module.split(".")
            prefix = parent_parts[: max(0, len(parent_parts) - level)]
            if module:
                return ".".join(prefix + module.split("."))
            return ".".join(prefix)
        return module

    def _index_file(self, path: Path) -> list[ImportEdge]:
        relative = str(path.relative_to(self.root))
        module = self._module_name(path)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError):
            return []

        edges: list[ImportEdge] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    edges.append(
                        ImportEdge(
                            source=module,
                            target=alias.name,
                            lineno=node.lineno,
                            import_name=alias.asname or alias.name,
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module is None and node.level == 0:
                    continue
                target = self._resolve_target(node.module or "", node.level, module)
                if target:
                    edges.append(
                        ImportEdge(
                            source=module,
                            target=target,
                            lineno=node.lineno,
                            import_name=node.module or ".",
                        )
                    )
        return edges

    def build(self) -> list[ImportEdge]:
        """Scan the project and build the import graph."""
        self._edges = []
        self._adjacency = defaultdict(set)
        if not self.root.exists():
            return self._edges

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            for edge in self._index_file(path):
                self._edges.append(edge)
                self._adjacency[edge.source].add(edge.target)
        return self._edges

    @property
    def edges(self) -> list[ImportEdge]:
        """Return import edges, building the graph on first access."""
        if not self._edges:
            self.build()
        return list(self._edges)

    @property
    def modules(self) -> set[str]:
        """Return all modules in the graph."""
        mods: set[str] = set()
        for edge in self.edges:
            mods.add(edge.source)
            mods.add(edge.target)
        return mods

    def dependents(self, module: str) -> list[str]:
        """Return modules that import the given module."""
        _ = self.edges
        return sorted({edge.source for edge in self._edges if edge.target == module})

    def dependencies(self, module: str) -> list[str]:
        """Return modules imported by the given module."""
        _ = self.edges
        return sorted(self._adjacency.get(module, set()))

    def find_cycles(self) -> list[list[str]]:
        """Detect circular import chains using DFS."""
        if not self._edges:
            self.build()

        cycles: list[list[str]] = []
        visited: set[str] = set()
        stack: set[str] = set()
        path: list[str] = []

        def dfs(node: str) -> None:
            visited.add(node)
            stack.add(node)
            path.append(node)
            for neighbor in sorted(self._adjacency.get(node, set())):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in stack:
                    start = path.index(neighbor)
                    cycle = path[start:] + [neighbor]
                    if cycle not in cycles:
                        cycles.append(cycle)
            path.pop()
            stack.remove(node)

        for module in sorted(self.modules):
            if module not in visited:
                dfs(module)
        return cycles

    def summary(self) -> str:
        """Return a human-readable summary of the import graph."""
        edges = self.edges
        if not edges:
            return f"No Python imports found in {self.root}"

        modules = self.modules
        cycles = self.find_cycles()
        lines = [
            f"Import graph: {self.root}",
            f"Modules: {len(modules)}",
            f"Import edges: {len(edges)}",
            f"Circular imports: {len(cycles)}",
        ]
        return "\n".join(lines)

    def to_context(self, module: str | None = None, max_edges: int = 80) -> str:
        """Build LLM context from import relationships."""
        edges = self.edges
        if module:
            edges = [
                e for e in edges if e.source == module or e.target == module
            ]
        if not edges:
            return self.summary()

        lines = [self.summary(), ""]
        if module:
            deps = self.dependencies(module)
            deps_on = self.dependents(module)
            lines.append(f"Module: {module}")
            if deps:
                lines.append(f"  imports: {', '.join(deps)}")
            if deps_on:
                lines.append(f"  imported by: {', '.join(deps_on)}")
            lines.append("")

        lines.append("Import edges:")
        for edge in edges[:max_edges]:
            lines.append(
                f"  {edge.source} -> {edge.target} @ line {edge.lineno} ({edge.import_name})"
            )
        if len(edges) > max_edges:
            lines.append(f"  ... and {len(edges) - max_edges} more")

        cycles = self.find_cycles()
        if cycles:
            lines.append("")
            lines.append("Circular imports:")
            for cycle in cycles[:10]:
                lines.append(f"  {' -> '.join(cycle)}")
        return "\n".join(lines)
