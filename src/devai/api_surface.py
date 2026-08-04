"""APISurfaceAnalyzer — map and analyze a Python package's public API."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class PublicSymbol:
    """A public function, class, or constant exposed by a module."""

    name: str
    kind: str
    path: str
    lineno: int
    documented: bool = False
    in_all: bool = False

    def format(self) -> str:
        """Return a single-line description."""
        flags: list[str] = []
        if self.in_all:
            flags.append("__all__")
        if not self.documented:
            flags.append("undocumented")
        suffix = f" [{', '.join(flags)}]" if flags else ""
        return f"{self.path}:{self.lineno} {self.kind} {self.name}{suffix}"


@dataclass
class ModuleSurface:
    """Public API surface for a single module."""

    path: str
    symbols: list[PublicSymbol] = field(default_factory=list)
    has_all: bool = False
    all_names: list[str] = field(default_factory=list)

    @property
    def public_count(self) -> int:
        return len(self.symbols)


@dataclass
class APISurfaceStats:
    """Aggregate API surface statistics."""

    modules: int
    public_symbols: int
    documented: int
    undocumented: int
    in_all: int
    modules_with_all: int
    coverage_pct: float = 0.0


class APISurfaceAnalyzer:
    """Analyze the public API surface of a Python project.

    Identifies public functions, classes, and module-level constants,
    checks ``__all__`` declarations, and flags undocumented exports.
    """

    def __init__(
        self,
        root: str,
        *,
        source_dir: str = "src",
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.source_dir = source_dir
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._modules: list[ModuleSurface] = []
        self._stats: APISurfaceStats | None = None

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _has_docstring(self, node: ast.AST) -> bool:
        return (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and ast.get_docstring(node) is not None
        )

    def _analyze_module(self, path: Path) -> ModuleSurface:
        relative = str(path.relative_to(self.root))
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError):
            return ModuleSurface(path=relative)

        all_names: list[str] = []
        has_all = False
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "__all__"
                and isinstance(node.value, (ast.List, ast.Tuple))
            ):
                has_all = True
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        all_names.append(elt.value)

        symbols: list[PublicSymbol] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue
                kind = "async function" if isinstance(node, ast.AsyncFunctionDef) else "function"
                symbols.append(
                    PublicSymbol(
                        name=node.name,
                        kind=kind,
                        path=relative,
                        lineno=node.lineno,
                        documented=self._has_docstring(node),
                        in_all=node.name in all_names,
                    )
                )
            elif isinstance(node, ast.ClassDef):
                if node.name.startswith("_"):
                    continue
                symbols.append(
                    PublicSymbol(
                        name=node.name,
                        kind="class",
                        path=relative,
                        lineno=node.lineno,
                        documented=self._has_docstring(node),
                        in_all=node.name in all_names,
                    )
                )
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and not target.id.startswith("_"):
                        if target.id in ("__all__", "__version__", "__author__"):
                            continue
                        symbols.append(
                            PublicSymbol(
                                name=target.id,
                                kind="constant",
                                path=relative,
                                lineno=node.lineno,
                                documented=False,
                                in_all=target.id in all_names,
                            )
                        )

        return ModuleSurface(
            path=relative,
            symbols=symbols,
            has_all=has_all,
            all_names=all_names,
        )

    def analyze(self) -> list[ModuleSurface]:
        """Scan the project and return per-module API surfaces."""
        if self._modules:
            return self._modules

        modules: list[ModuleSurface] = []
        search_root = self.root / self.source_dir
        if not search_root.is_dir():
            search_root = self.root

        for path in sorted(search_root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            modules.append(self._analyze_module(path))

        self._modules = modules
        self._stats = self._build_stats(modules)
        return modules

    def _build_stats(self, modules: list[ModuleSurface]) -> APISurfaceStats:
        symbols = [s for m in modules for s in m.symbols]
        documented = sum(1 for s in symbols if s.documented)
        undocumented = len(symbols) - documented
        in_all = sum(1 for s in symbols if s.in_all)
        modules_with_all = sum(1 for m in modules if m.has_all)
        coverage = round(documented / len(symbols) * 100, 1) if symbols else 100.0
        return APISurfaceStats(
            modules=len(modules),
            public_symbols=len(symbols),
            documented=documented,
            undocumented=undocumented,
            in_all=in_all,
            modules_with_all=modules_with_all,
            coverage_pct=coverage,
        )

    @property
    def modules(self) -> list[ModuleSurface]:
        """Return analyzed modules (runs analysis on first access)."""
        if not self._modules:
            self.analyze()
        return self._modules

    @property
    def symbols(self) -> list[PublicSymbol]:
        """Return all public symbols across the project."""
        return [s for m in self.modules for s in m.symbols]

    @property
    def stats(self) -> APISurfaceStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def undocumented(self) -> list[PublicSymbol]:
        """Return public symbols missing docstrings."""
        return [s for s in self.symbols if not s.documented and s.kind != "constant"]

    def health_score(self) -> float:
        """Return a 0–100 score based on API documentation coverage."""
        stats = self.stats
        if stats.public_symbols == 0:
            return 100.0
        score = stats.coverage_pct
        if stats.modules > 0:
            all_ratio = stats.modules_with_all / stats.modules
            score = score * 0.85 + all_ratio * 100.0 * 0.15
        return round(min(100.0, max(0.0, score)), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        stats = self.stats
        lines = [
            f"Modules: {stats.modules}, Public symbols: {stats.public_symbols}",
            f"Documented: {stats.documented} ({stats.coverage_pct}%)",
            f"Undocumented: {stats.undocumented}",
            f"In __all__: {stats.in_all}, Modules with __all__: {stats.modules_with_all}",
            f"API health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing the public API."""
        lines = [
            "Public API surface analysis:",
            self.summary(),
            "",
            "Undocumented public symbols:",
        ]
        gaps = self.undocumented()[:limit]
        if not gaps:
            lines.append("All public functions and classes are documented.")
        else:
            for sym in gaps:
                lines.append(sym.format())
        return "\n".join(lines)
