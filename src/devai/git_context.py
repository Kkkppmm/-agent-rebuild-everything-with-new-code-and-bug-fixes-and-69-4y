"""Git-aware context helpers for DevAI developer workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from devai.utils.diff import get_git_diff, summarize_diff

if TYPE_CHECKING:
    from devai.assistant import CodeAssistant


@dataclass
class GitContext:
    """Wrap git state for one-line AI reviews of local changes."""

    repo_path: Path = field(default_factory=Path.cwd)
    staged: bool = False
    base: str | None = None
    path_filter: str | None = None

    def diff(self) -> str:
        """Return the unified diff for the configured scope."""
        return get_git_diff(
            staged=self.staged,
            base=self.base,
            path=self.path_filter,
        )

    def changed_files(self) -> list[str]:
        """List files changed in the current diff."""
        from devai.utils.diff import parse_changed_files

        return parse_changed_files(self.diff())

    def summarize(self) -> dict[str, int | list[str]]:
        """Summarize additions, deletions, and changed files."""
        return summarize_diff(self.diff())

    def review_changes(self, assistant: CodeAssistant) -> str:
        """Review the current git diff."""
        return assistant.review_diff(self.diff())

    def commit_message(self, assistant: CodeAssistant) -> str:
        """Generate a commit message from staged or unstaged changes."""
        return assistant.commit_message(self.diff())

    def pr_description(self, assistant: CodeAssistant, title: str = "") -> str:
        """Generate a pull request description from the diff."""
        return assistant.pr_description(title, self.diff())

    def summarize_changes(self, assistant: CodeAssistant) -> str:
        """Summarize what changed in the diff."""
        return assistant.summarize_changes(self.diff())

    @classmethod
    def staged_changes(cls, repo_path: str | Path | None = None) -> GitContext:
        """Context for staged (cached) changes."""
        return cls(repo_path=Path(repo_path or Path.cwd()), staged=True)

    @classmethod
    def unstaged_changes(cls, repo_path: str | Path | None = None) -> GitContext:
        """Context for unstaged working-tree changes."""
        return cls(repo_path=Path(repo_path or Path.cwd()), staged=False)

    @classmethod
    def against(cls, base: str, repo_path: str | Path | None = None) -> GitContext:
        """Context for changes against a base ref (e.g. ``main``)."""
        return cls(repo_path=Path(repo_path or Path.cwd()), base=base)
