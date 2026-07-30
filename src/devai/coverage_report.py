"""CoverageReport — parse and summarize coverage.py XML reports."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FileCoverage:
    """Coverage data for a single file."""

    path: str
    lines_valid: int
    lines_covered: int
    line_rate: float
    missing_lines: list[int] = field(default_factory=list)

    @property
    def coverage_pct(self) -> float:
        if self.lines_valid == 0:
            return 100.0
        return round(100.0 * self.lines_covered / self.lines_valid, 1)

    def format(self) -> str:
        """Return a single-line description."""
        missing = f", missing lines: {self.missing_lines[:10]}" if self.missing_lines else ""
        if len(self.missing_lines) > 10:
            missing += f" (+{len(self.missing_lines) - 10} more)"
        return f"{self.path}: {self.coverage_pct}% ({self.lines_covered}/{self.lines_valid}){missing}"


@dataclass
class CoverageSummary:
    """Aggregate coverage statistics."""

    lines_valid: int
    lines_covered: int
    line_rate: float
    files: int
    files_full: int
    files_partial: int
    files_empty: int

    @property
    def coverage_pct(self) -> float:
        if self.lines_valid == 0:
            return 100.0
        return round(100.0 * self.lines_covered / self.lines_valid, 1)


class CoverageReport:
    """Parse coverage.py XML output and summarize test coverage."""

    def __init__(self, source: str | Path) -> None:
        if isinstance(source, Path) or (isinstance(source, str) and Path(source).is_file()):
            path = Path(source)
            self._xml_text = path.read_text(encoding="utf-8", errors="replace")
            self._source_path = str(path)
        else:
            self._xml_text = source
            self._source_path = "<inline>"
        self._files: list[FileCoverage] = []
        self._summary: CoverageSummary | None = None

    def _parse_line_rate(self, value: str | None) -> float:
        if not value:
            return 0.0
        try:
            return float(value)
        except ValueError:
            return 0.0

    def _parse_missing_lines(self, lines_elem: ET.Element | None) -> list[int]:
        if lines_elem is None:
            return []
        missing: list[int] = []
        for line in lines_elem.findall("line"):
            hits = line.get("hits")
            if hits == "0" or hits is None:
                num = line.get("number")
                if num:
                    try:
                        missing.append(int(num))
                    except ValueError:
                        continue
        return sorted(missing)

    def parse(self) -> CoverageSummary:
        """Parse the XML report and return aggregate coverage."""
        if self._summary is not None:
            return self._summary

        try:
            root = ET.fromstring(self._xml_text)
        except ET.ParseError as e:
            raise ValueError(f"Invalid coverage XML: {e}") from e

        files: list[FileCoverage] = []
        for pkg in root.findall(".//package"):
            for class_elem in pkg.findall("classes/class"):
                filename = class_elem.get("filename") or class_elem.get("name") or "unknown"
                lines_valid = int(class_elem.get("lines-valid") or 0)
                lines_covered = int(class_elem.get("lines-covered") or 0)
                line_rate = self._parse_line_rate(class_elem.get("line-rate"))
                lines_elem = class_elem.find("lines")
                missing = self._parse_missing_lines(lines_elem)
                files.append(
                    FileCoverage(
                        path=filename,
                        lines_valid=lines_valid,
                        lines_covered=lines_covered,
                        line_rate=line_rate,
                        missing_lines=missing,
                    )
                )

        self._files = files

        total_valid = sum(f.lines_valid for f in files)
        total_covered = sum(f.lines_covered for f in files)
        files_full = sum(1 for f in files if f.lines_valid > 0 and f.lines_covered == f.lines_valid)
        files_empty = sum(1 for f in files if f.lines_valid == 0)
        files_partial = len(files) - files_full - files_empty

        line_rate = total_covered / total_valid if total_valid > 0 else 1.0
        self._summary = CoverageSummary(
            lines_valid=total_valid,
            lines_covered=total_covered,
            line_rate=line_rate,
            files=len(files),
            files_full=files_full,
            files_partial=files_partial,
            files_empty=files_empty,
        )
        return self._summary

    @property
    def stats(self) -> CoverageSummary:
        """Return aggregate coverage statistics."""
        return self.parse()

    def files(self) -> list[FileCoverage]:
        """Return per-file coverage data sorted by coverage percentage."""
        self.parse()
        return sorted(self._files, key=lambda f: (f.coverage_pct, f.path))

    def uncovered_files(self, threshold_pct: float = 100.0) -> list[FileCoverage]:
        """Return files with coverage below the threshold."""
        self.parse()
        return [f for f in self._files if f.coverage_pct < threshold_pct and f.lines_valid > 0]

    def worst_files(self, limit: int = 10) -> list[FileCoverage]:
        """Return files with the lowest coverage."""
        self.parse()
        eligible = [f for f in self._files if f.lines_valid > 0]
        return sorted(eligible, key=lambda f: (f.coverage_pct, -f.lines_valid))[:limit]

    def summary(self) -> str:
        """Return a human-readable summary."""
        stats = self.parse()
        lines = [
            f"Coverage: {stats.coverage_pct}% ({stats.lines_covered}/{stats.lines_valid} lines)",
            f"Files: {stats.files} total, {stats.files_full} fully covered, "
            f"{stats.files_partial} partial, {stats.files_empty} empty",
            f"Source: {self._source_path}",
        ]
        uncovered = self.uncovered_files(100.0)
        if uncovered:
            lines.append(f"Files below 100% coverage: {len(uncovered)}")
        return "\n".join(lines)

    def to_context(self, limit: int = 20) -> str:
        """Build LLM-ready context describing test coverage gaps."""
        self.parse()
        lines = [
            "Test coverage analysis:",
            self.summary(),
            "",
            "Files with lowest coverage:",
        ]
        worst = self.worst_files(limit)
        if not worst:
            lines.append("No coverage data found.")
        else:
            for fc in worst:
                lines.append(fc.format())
        return "\n".join(lines)
