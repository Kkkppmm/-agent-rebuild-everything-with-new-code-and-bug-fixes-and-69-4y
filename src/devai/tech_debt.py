"""TechDebtScanner — scan for TODO, FIXME, HACK, and other tech-debt markers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

DEFAULT_MARKERS = ("TODO", "FIXME", "HACK", "XXX", "BUG", "DEPRECATED", "OPTIMIZE", "REVIEW")

MARKER_PATTERN = re.compile(
    r"(?:#|//|/\*|\*)\s*(" + "|".join(DEFAULT_MARKERS) + r")\b[:\s]*(.*)",
    re.IGNORECASE,
)


@dataclass
class TechDebtItem:
    """A tech-debt marker found in source code."""

    path: str
    lineno: int
    marker: str
    message: str

    def format(self) -> str:
        """Return a single-line description."""
        msg = self.message.strip() or "(no message)"
        return f"{self.path}:{self.lineno} [{self.marker.upper()}] {msg}"


@dataclass
class TechDebtStats:
    """Aggregate tech-debt statistics."""

    total_items: int
    by_marker: dict[str, int] = field(default_factory=dict)
    files_with_debt: int = 0
    debt_density: float = 0.0


class TechDebtScanner:
    """Scan source files for tech-debt comment markers.

    Supports Python, JavaScript/TypeScript, Go, Rust, Java, C/C++, and shell files.
  """

    EXTENSIONS = {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".go",
        ".rs",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".rb",
        ".php",
        ".swift",
        ".kt",
        ".scala",
        ".sh",
        ".bash",
        ".zsh",
        ".yaml",
        ".yml",
        ".toml",
        ".md",
    }

    def __init__(
        self,
        root: str,
        *,
        markers: tuple[str, ...] | None = None,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.markers = markers or DEFAULT_MARKERS
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._items: list[TechDebtItem] = []
        self._stats: TechDebtStats | None = None
        self._files_scanned = 0
        self._pattern = re.compile(
            r"(?:#|//|/\*|\*)\s*(" + "|".join(self.markers) + r")\b[:\s]*(.*)",
            re.IGNORECASE,
        )

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix.lower() not in self.EXTENSIONS

    def scan(self) -> list[TechDebtItem]:
        """Scan the project and return tech-debt items."""
        if self._items:
            return self._items

        items: list[TechDebtItem] = []
        files_scanned = 0
        files_with_debt: set[str] = set()

        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            found_in_file = False

            for lineno, line in enumerate(text.splitlines(), start=1):
                match = self._pattern.search(line)
                if not match:
                    continue
                marker = match.group(1).upper()
                message = match.group(2).strip()
                items.append(
                    TechDebtItem(
                        path=rel,
                        lineno=lineno,
                        marker=marker,
                        message=message,
                    )
                )
                found_in_file = True

            if found_in_file:
                files_with_debt.add(rel)

        self._items = items
        self._files_scanned = files_scanned

        by_marker: dict[str, int] = {}
        for item in items:
            by_marker[item.marker] = by_marker.get(item.marker, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(items) / files_scanned, 1)

        stats = TechDebtStats(
            total_items=len(items),
            by_marker=by_marker,
            files_with_debt=len(files_with_debt),
            debt_density=density,
        )
        self._stats = stats
        return items

    @property
    def stats(self) -> TechDebtStats:
        """Return aggregate tech-debt statistics."""
        if self._stats is None:
            self.scan()
        return self._stats  # type: ignore[return-value]

    def by_marker(self, marker: str) -> list[TechDebtItem]:
        """Return items for a specific marker type."""
        marker = marker.upper()
        return [i for i in self.scan() if i.marker == marker]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no tech debt markers)."""
        self.scan()
        if self._files_scanned == 0:
            return 100.0
        ratio = len(self._items) / self._files_scanned
        critical = sum(1 for i in self._items if i.marker in ("FIXME", "BUG", "HACK"))
        penalty = ratio * 80.0 + critical * 3.0
        return round(max(0.0, 100.0 - penalty), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.scan()
        stats = self.stats
        lines = [
            f"Tech debt: {stats.total_items} markers in {stats.files_with_debt} files "
            f"({self._files_scanned} scanned)",
            f"Density: {stats.debt_density} markers per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_marker:
            markers = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_marker.items()))
            lines.append(f"By marker: {markers}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing tech debt."""
        self.scan()
        lines = [
            "Tech debt scan:",
            self.summary(),
            "",
            "Markers found:",
        ]
        if not self._items:
            lines.append("No tech-debt markers found.")
        else:
            for item in self._items[:limit]:
                lines.append(item.format())
            if len(self._items) > limit:
                lines.append(f"... and {len(self._items) - limit} more")
        return "\n".join(lines)
