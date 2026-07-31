"""ComplexityHotspotAnalyzer — prioritize files for refactoring by complexity debt."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from devai.code_metrics import CodeMetrics, FunctionMetrics
from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class ComplexityHotspot:
    """A file ranked by complexity concentration."""

    path: str
    score: float
    sloc: int
    functions: int
    max_complexity: int
    avg_complexity: float
    high_complexity_count: int
    top_functions: list[str] = field(default_factory=list)

    def format(self) -> str:
        """Return a single-line description."""
        return (
            f"{self.path} score={self.score:.1f} "
            f"max_cx={self.max_complexity} high={self.high_complexity_count} "
            f"({self.sloc} sloc, {self.functions} fn)"
        )


@dataclass
class HotspotStats:
    """Aggregate hotspot statistics."""

    files_analyzed: int
    hotspots: int
    total_high_complexity: int
    worst_score: float
    avg_score: float


class ComplexityHotspotAnalyzer:
    """Rank files by complexity debt to guide refactoring priorities.

    Combines per-file cyclomatic complexity, high-complexity function counts,
    and source size into a hotspot score. Higher scores indicate files that
    would benefit most from simplification.
    """

    def __init__(
        self,
        root: str,
        *,
        complexity_threshold: int = 10,
        ignore_dirs: set[str] | None = None,
        limit: int = 20,
    ) -> None:
        self.root = Path(root)
        self.complexity_threshold = complexity_threshold
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.limit = limit
        self._hotspots: list[ComplexityHotspot] = []
        self._stats: HotspotStats | None = None
        self._metrics: CodeMetrics | None = None

    def _hotspot_score(
        self,
        max_cx: int,
        avg_cx: float,
        high_count: int,
        sloc: int,
        functions: int,
    ) -> float:
        if functions == 0:
            return 0.0
        excess = sum(max(0, self.complexity_threshold - 1) for _ in range(high_count))
        size_factor = min(2.0, sloc / 200.0) if sloc else 0.5
        return round(
            max_cx * 3.0 + avg_cx * 2.0 + high_count * 5.0 + excess * 0.5 + size_factor,
            1,
        )

    def _build_hotspot(
        self,
        path: str,
        sloc: int,
        functions: int,
        max_cx: int,
        avg_cx: float,
        fn_metrics: list[FunctionMetrics],
    ) -> ComplexityHotspot:
        high = [f for f in fn_metrics if f.complexity >= self.complexity_threshold]
        top = sorted(fn_metrics, key=lambda f: f.complexity, reverse=True)[:3]
        score = self._hotspot_score(max_cx, avg_cx, len(high), sloc, functions)
        return ComplexityHotspot(
            path=path,
            score=score,
            sloc=sloc,
            functions=functions,
            max_complexity=max_cx,
            avg_complexity=avg_cx,
            high_complexity_count=len(high),
            top_functions=[f.name for f in top],
        )

    def analyze(self) -> list[ComplexityHotspot]:
        """Scan the project and return ranked complexity hotspots."""
        if self._hotspots:
            return self._hotspots

        metrics = CodeMetrics(
            str(self.root),
            ignore_dirs=self.ignore_dirs,
            complexity_threshold=self.complexity_threshold,
        )
        metrics.analyze()
        self._metrics = metrics

        by_file: dict[str, list[FunctionMetrics]] = {}
        for fn in metrics.functions:
            by_file.setdefault(fn.path, []).append(fn)

        hotspots: list[ComplexityHotspot] = []
        for fm in metrics.analyze():
            if fm.functions == 0:
                continue
            hotspots.append(
                self._build_hotspot(
                    fm.path,
                    fm.sloc,
                    fm.functions,
                    fm.max_complexity,
                    fm.avg_complexity,
                    by_file.get(fm.path, []),
                )
            )

        hotspots.sort(key=lambda h: h.score, reverse=True)
        self._hotspots = hotspots[: self.limit]
        self._stats = self._build_stats(hotspots)
        return self._hotspots

    def _build_stats(self, all_hotspots: list[ComplexityHotspot]) -> HotspotStats:
        scores = [h.score for h in all_hotspots if h.score > 0]
        return HotspotStats(
            files_analyzed=len(all_hotspots),
            hotspots=sum(1 for h in all_hotspots if h.high_complexity_count > 0),
            total_high_complexity=sum(h.high_complexity_count for h in all_hotspots),
            worst_score=max(scores) if scores else 0.0,
            avg_score=round(sum(scores) / len(scores), 1) if scores else 0.0,
        )

    @property
    def hotspots(self) -> list[ComplexityHotspot]:
        """Return ranked hotspots (runs analysis on first access)."""
        if not self._hotspots:
            self.analyze()
        return self._hotspots

    @property
    def stats(self) -> HotspotStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0–100 score — lower hotspot density means higher health."""
        stats = self.stats
        if stats.files_analyzed == 0:
            return 100.0
        hotspot_ratio = stats.hotspots / stats.files_analyzed
        penalty = min(100.0, hotspot_ratio * 120.0 + stats.total_high_complexity * 2.0)
        return round(max(0.0, 100.0 - penalty), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        stats = self.stats
        lines = [
            f"Files analyzed: {stats.files_analyzed}, Hotspots: {stats.hotspots}",
            f"High-complexity functions: {stats.total_high_complexity}",
            f"Worst score: {stats.worst_score}, Avg score: {stats.avg_score}",
            f"Hotspot health score: {self.health_score()}/100",
            "",
            "Top hotspots:",
        ]
        for hotspot in self.hotspots[:10]:
            lines.append(f"  {hotspot.format()}")
        return "\n".join(lines)

    def to_context(self, limit: int = 15) -> str:
        """Build LLM-ready context describing complexity hotspots."""
        lines = [
            "Complexity hotspot analysis:",
            self.summary(),
            "",
            "Refactoring priorities:",
        ]
        for hotspot in self.hotspots[:limit]:
            lines.append(hotspot.format())
            if hotspot.top_functions:
                lines.append(f"    worst: {', '.join(hotspot.top_functions)}")
        return "\n".join(lines)
