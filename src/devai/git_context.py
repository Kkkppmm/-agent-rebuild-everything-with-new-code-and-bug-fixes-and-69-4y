"""Git-aware context for DevAI reviews and programs."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from devai.tools.code_utils import git_diff


@dataclass
class GitContext:
    """Collect git repository context for AI-assisted developer workflows."""

    path: str | Path = "."
    _cache: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path).resolve()

    def branch(self) -> str:
        if "branch" not in self._cache:
            self._cache["branch"] = self._run_git("rev-parse", "--abbrev-ref", "HEAD")
        return self._cache["branch"]

    def commit(self) -> str:
        if "commit" not in self._cache:
            self._cache["commit"] = self._run_git("rev-parse", "--short", "HEAD")
        return self._cache["commit"]

    def status(self) -> str:
        if "status" not in self._cache:
            self._cache["status"] = self._run_git("status", "--short")
        return self._cache["status"]

    def diff(self, *, staged: bool = False) -> str:
        key = f"diff:{'staged' if staged else 'unstaged'}"
        if key not in self._cache:
            self._cache[key] = git_diff(staged=staged)
        return self._cache[key]

    def recent_commits(self, count: int = 5) -> str:
        return self._run_git("log", f"-{count}", "--oneline")

    def is_repo(self) -> bool:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=self.path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def to_context(self, *, include_diff: bool = True) -> dict[str, str]:
        """Build a context dict suitable for DevProgram or DevWorkflow."""
        if not self.is_repo():
            return {"git_error": "Not a git repository"}
        context = {
            "branch": self.branch(),
            "commit": self.commit(),
            "status": self.status(),
            "recent_commits": self.recent_commits(),
        }
        if include_diff:
            context["diff"] = self.diff()
            context["staged_diff"] = self.diff(staged=True)
        return context

    def review_context(self) -> str:
        """Format git context as markdown for LLM prompts."""
        if not self.is_repo():
            return "Not a git repository."
        lines = [
            f"Branch: {self.branch()}",
            f"Commit: {self.commit()}",
            "",
            "## Status",
            self.status() or "(clean)",
            "",
            "## Recent commits",
            self.recent_commits(),
            "",
            "## Diff",
            self.diff() or "(no changes)",
        ]
        return "\n".join(lines)

    def _run_git(self, *args: str) -> str:
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=self.path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return result.stderr.strip() or f"git {' '.join(args)} failed"
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return str(exc)
