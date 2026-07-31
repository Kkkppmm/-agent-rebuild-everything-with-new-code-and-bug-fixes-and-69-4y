"""Compare code versions and review changes with AI."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path

from devai.assistant import CodeAssistant
from devai.utils.diff import summarize_diff


@dataclass(frozen=True)
class CompareResult:
    """Result of comparing two code versions."""

    before_label: str
    after_label: str
    diff: str
    additions: int
    deletions: int
    changed_lines: int

    @property
    def has_changes(self) -> bool:
        return bool(self.diff.strip())


def _read_source(source: str | Path) -> tuple[str, str]:
    path = Path(source)
    if path.exists() and path.is_file():
        return path.read_text(encoding="utf-8", errors="replace"), str(path)
    return str(source), "<string>"


def _unified_diff(
    before: str,
    after: str,
    before_label: str,
    after_label: str,
) -> str:
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    if before_lines and not before_lines[-1].endswith("\n"):
        before_lines[-1] += "\n"
    if after_lines and not after_lines[-1].endswith("\n"):
        after_lines[-1] += "\n"
    return "".join(
        difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile=before_label,
            tofile=after_label,
        )
    )


class CodeComparer:
    """Compare two code versions and optionally review changes with AI."""

    def __init__(self, assistant: CodeAssistant) -> None:
        self._assistant = assistant

    def compare(
        self,
        before: str | Path,
        after: str | Path,
        *,
        before_label: str | None = None,
        after_label: str | None = None,
    ) -> CompareResult:
        """Generate a unified diff between two code sources."""
        before_text, before_name = _read_source(before)
        after_text, after_name = _read_source(after)
        label_before = before_label or before_name
        label_after = after_label or after_name
        diff = _unified_diff(before_text, after_text, label_before, label_after)
        stats = summarize_diff(diff) if diff else {"additions": 0, "deletions": 0}
        return CompareResult(
            before_label=label_before,
            after_label=label_after,
            diff=diff,
            additions=int(stats.get("additions", 0)),
            deletions=int(stats.get("deletions", 0)),
            changed_lines=int(stats.get("additions", 0)) + int(stats.get("deletions", 0)),
        )

    def review_changes(
        self,
        before: str | Path,
        after: str | Path,
        *,
        before_label: str | None = None,
        after_label: str | None = None,
    ) -> str:
        """Compare two sources and return an AI review of the changes."""
        result = self.compare(before, after, before_label=before_label, after_label=after_label)
        if not result.has_changes:
            return "No changes detected."
        return self._assistant.review_diff(result.diff)

    def summarize_changes(
        self,
        before: str | Path,
        after: str | Path,
        *,
        audience: str = "developers",
        before_label: str | None = None,
        after_label: str | None = None,
    ) -> str:
        """Compare two sources and summarize changes for release notes or PRs."""
        result = self.compare(before, after, before_label=before_label, after_label=after_label)
        if not result.has_changes:
            return "No changes detected."
        return self._assistant.summarize_changes(result.diff, audience=audience)

    def compare_files(self, path_a: str | Path, path_b: str | Path) -> CompareResult:
        """Compare two files on disk."""
        return self.compare(path_a, path_b)
