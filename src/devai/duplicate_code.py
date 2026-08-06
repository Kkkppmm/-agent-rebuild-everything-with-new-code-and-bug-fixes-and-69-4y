"""DuplicateCodeDetector — find duplicate and near-duplicate code blocks."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class DuplicateBlock:
    """A single occurrence of a duplicated code block."""

    path: str
    start_line: int
    end_line: int
    lines: int

    def format(self) -> str:
        """Return a single-line description."""
        return f"{self.path}:{self.start_line}-{self.end_line} ({self.lines} lines)"


@dataclass
class DuplicateCluster:
    """A group of duplicate code blocks sharing the same normalized content."""

    fingerprint: str
    blocks: list[DuplicateBlock] = field(default_factory=list)
    line_count: int = 0

    @property
    def occurrences(self) -> int:
        """Number of duplicate occurrences."""
        return len(self.blocks)

    def format(self) -> str:
        """Return a multi-line description."""
        locations = ", ".join(b.format() for b in self.blocks[:5])
        extra = f" (+{len(self.blocks) - 5} more)" if len(self.blocks) > 5 else ""
        return f"{self.line_count} lines x {self.occurrences} occurrences: {locations}{extra}"


@dataclass
class DuplicateStats:
    """Aggregate duplicate-code statistics."""

    total_clusters: int
    total_blocks: int
    duplicated_lines: int
    files_affected: int
    duplication_ratio: float = 0.0


class DuplicateCodeDetector:
    """Find duplicate code blocks across a project using normalized line hashing.

    Strips comments and whitespace, then compares sliding windows of source lines
    to detect copy-pasted or near-identical blocks.
    """

    EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".php"}

    def __init__(
        self,
        root: str,
        *,
        min_lines: int = 5,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.min_lines = min_lines
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._clusters: list[DuplicateCluster] = []
        self._stats: DuplicateStats | None = None
        self._total_sloc = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix.lower() not in self.EXTENSIONS

    def _normalize_line(self, line: str) -> str:
        stripped = line.strip()
        if not stripped:
            return ""
        if stripped.startswith("#"):
            return ""
        if "//" in stripped:
            stripped = stripped.split("//", 1)[0].strip()
        return re.sub(r"\s+", " ", stripped)

    def _fingerprint(self, lines: list[str]) -> str:
        normalized = "\n".join(lines)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def _scan_file(self, path: Path) -> dict[str, list[DuplicateBlock]]:
        try:
            raw_lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            return {}

        rel = str(path.relative_to(self.root))
        normalized = [self._normalize_line(line) for line in raw_lines]
        self._total_sloc += sum(1 for line in normalized if line)

        windows: dict[str, list[DuplicateBlock]] = {}
        n = len(normalized)
        window = self.min_lines

        for start in range(n - window + 1):
            chunk = normalized[start : start + window]
            if sum(1 for line in chunk if line) < window // 2:
                continue
            fp = self._fingerprint(chunk)
            block = DuplicateBlock(
                path=rel,
                start_line=start + 1,
                end_line=start + window,
                lines=window,
            )
            windows.setdefault(fp, []).append(block)

        return windows

    def analyze(self) -> list[DuplicateCluster]:
        """Scan the project and return duplicate clusters."""
        if self._clusters:
            return self._clusters

        global_map: dict[str, list[DuplicateBlock]] = {}
        self._total_sloc = 0

        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue
            for fp, blocks in self._scan_file(path).items():
                global_map.setdefault(fp, []).extend(blocks)

        clusters: list[DuplicateCluster] = []
        files_affected: set[str] = set()
        duplicated_lines = 0

        for fp, blocks in global_map.items():
            if len(blocks) < 2:
                continue
            cluster = DuplicateCluster(
                fingerprint=fp,
                blocks=sorted(blocks, key=lambda b: (b.path, b.start_line)),
                line_count=blocks[0].lines,
            )
            clusters.append(cluster)
            duplicated_lines += cluster.line_count * (cluster.occurrences - 1)
            for block in blocks:
                files_affected.add(block.path)

        clusters.sort(key=lambda c: (-c.occurrences, -c.line_count))
        self._clusters = clusters

        total_blocks = sum(c.occurrences for c in clusters)
        ratio = 0.0
        if self._total_sloc:
            ratio = round(100.0 * duplicated_lines / self._total_sloc, 2)

        self._stats = DuplicateStats(
            total_clusters=len(clusters),
            total_blocks=total_blocks,
            duplicated_lines=duplicated_lines,
            files_affected=len(files_affected),
            duplication_ratio=ratio,
        )
        return clusters

    @property
    def stats(self) -> DuplicateStats:
        """Return aggregate duplicate-code statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no duplicates)."""
        self.analyze()
        if not self._clusters:
            return 100.0
        ratio = self.stats.duplication_ratio
        cluster_penalty = min(40.0, self.stats.total_clusters * 5.0)
        return round(max(0.0, 100.0 - ratio * 2.0 - cluster_penalty), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Duplicate code: {stats.total_clusters} clusters, "
            f"{stats.total_blocks} blocks in {stats.files_affected} files",
            f"Duplicated lines: {stats.duplicated_lines} ({stats.duplication_ratio}% of SLOC)",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 20) -> str:
        """Build LLM-ready context describing duplicate code."""
        self.analyze()
        lines = [
            "Duplicate code analysis:",
            self.summary(),
            "",
            "Clusters:",
        ]
        if not self._clusters:
            lines.append("No duplicate blocks found.")
        else:
            for cluster in self._clusters[:limit]:
                lines.append(f"  - {cluster.format()}")
            if len(self._clusters) > limit:
                lines.append(f"... and {len(self._clusters) - limit} more clusters")
        return "\n".join(lines)
