"""ModuleCouplingAnalyzer — measure afferent/efferent coupling from import graphs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from devai.import_graph import ImportGraph
from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class ModuleCoupling:
    """Coupling metrics for a single module."""

    module: str
    afferent: int
    efferent: int
    instability: float

    def format(self) -> str:
        """Return a single-line description."""
        return (
            f"{self.module}: Ca={self.afferent}, Ce={self.efferent}, "
            f"I={self.instability:.2f}"
        )


@dataclass
class CouplingStats:
    """Aggregate module coupling statistics."""

    total_modules: int
    avg_instability: float
    max_instability: float
    circular_imports: int
    highly_coupled: int = 0


class ModuleCouplingAnalyzer:
    """Measure module coupling using import dependency graphs.

    Computes per-module:
    - **Afferent coupling (Ca)** — number of modules that import this module
    - **Efferent coupling (Ce)** — number of modules this module imports
    - **Instability (I)** — Ce / (Ca + Ce), ranging from 0 (stable) to 1 (volatile)
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        instability_threshold: float = 0.8,
        limit: int = 20,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.instability_threshold = instability_threshold
        self.limit = limit
        self._coupling: list[ModuleCoupling] = []
        self._stats: CouplingStats | None = None
        self._graph: ImportGraph | None = None

    def _build_graph(self) -> ImportGraph:
        if self._graph is None:
            self._graph = ImportGraph(str(self.root), ignore_dirs=self.ignore_dirs)
            self._graph.build()
        return self._graph

    def analyze(self) -> list[ModuleCoupling]:
        """Compute coupling metrics for all modules in the project."""
        if self._coupling:
            return list(self._coupling)

        graph = self._build_graph()
        modules = graph.modules
        if not modules:
            self._stats = CouplingStats(
                total_modules=0,
                avg_instability=0.0,
                max_instability=0.0,
                circular_imports=0,
            )
            return []

        coupling_list: list[ModuleCoupling] = []
        for module in sorted(modules):
            afferent = len(graph.dependents(module))
            efferent = len(graph.dependencies(module))
            total = afferent + efferent
            instability = efferent / total if total > 0 else 0.0
            coupling_list.append(
                ModuleCoupling(
                    module=module,
                    afferent=afferent,
                    efferent=efferent,
                    instability=round(instability, 3),
                )
            )

        self._coupling = sorted(coupling_list, key=lambda c: c.instability, reverse=True)
        cycles = graph.find_cycles()
        highly_coupled = sum(
            1 for c in self._coupling if c.instability >= self.instability_threshold
        )
        instabilities = [c.instability for c in self._coupling]
        self._stats = CouplingStats(
            total_modules=len(self._coupling),
            avg_instability=round(sum(instabilities) / len(instabilities), 3),
            max_instability=max(instabilities),
            circular_imports=len(cycles),
            highly_coupled=highly_coupled,
        )
        return list(self._coupling)

    @property
    def coupling(self) -> list[ModuleCoupling]:
        """Return coupling metrics (runs analysis on first access)."""
        if not self._coupling:
            self.analyze()
        return list(self._coupling)

    @property
    def stats(self) -> CouplingStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats

    def unstable_modules(self) -> list[ModuleCoupling]:
        """Return modules with instability >= threshold."""
        return [c for c in self.coupling if c.instability >= self.instability_threshold]

    def health_score(self) -> float:
        """Return a 0–100 health score (higher is better)."""
        stats = self.stats
        if stats.total_modules == 0:
            return 100.0
        cycle_penalty = min(40.0, stats.circular_imports * 15.0)
        instability_penalty = min(40.0, stats.avg_instability * 50.0)
        coupled_penalty = min(20.0, stats.highly_coupled * 4.0)
        return max(0.0, round(100.0 - cycle_penalty - instability_penalty - coupled_penalty, 1))

    def summary(self) -> str:
        """Return a human-readable summary."""
        stats = self.stats
        lines = [
            f"Module coupling: {self.root}",
            f"Modules: {stats.total_modules}",
            f"Avg instability: {stats.avg_instability:.2f}",
            f"Circular imports: {stats.circular_imports}",
            f"Highly coupled modules: {stats.highly_coupled}",
            f"Health score: {self.health_score():.0f}/100",
        ]
        unstable = self.unstable_modules()[:self.limit]
        if unstable:
            lines.append("")
            lines.append("Most unstable modules:")
            for mod in unstable:
                lines.append(f"  {mod.format()}")
        return "\n".join(lines)

    def to_context(self, max_modules: int = 25) -> str:
        """Build LLM-ready context describing module coupling."""
        graph = self._build_graph()
        lines = [self.summary(), ""]
        cycles = graph.find_cycles()
        if cycles:
            lines.append("Circular import chains:")
            for cycle in cycles[:10]:
                lines.append(f"  {' -> '.join(cycle)}")
            if len(cycles) > 10:
                lines.append(f"  ... and {len(cycles) - 10} more")
            lines.append("")

        lines.append("Module coupling (top unstable):")
        for mod in self.coupling[:max_modules]:
            lines.append(f"  {mod.format()}")
        if len(self.coupling) > max_modules:
            lines.append(f"  ... and {len(self.coupling) - max_modules} more")
        return "\n".join(lines)
