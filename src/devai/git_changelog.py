"""GitChangelog — generate changelog text from git commit history."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommitInfo:
    """A parsed git commit."""

    hash: str
    subject: str
    author: str
    category: str = "other"


CATEGORY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("feat", re.compile(r"^(feat|feature)(\(.+\))?:", re.IGNORECASE)),
    ("fix", re.compile(r"^(fix|bugfix)(\(.+\))?:", re.IGNORECASE)),
    ("docs", re.compile(r"^docs(\(.+\))?:", re.IGNORECASE)),
    ("refactor", re.compile(r"^refactor(\(.+\))?:", re.IGNORECASE)),
    ("test", re.compile(r"^test(\(.+\))?:", re.IGNORECASE)),
    ("chore", re.compile(r"^(chore|ci|build)(\(.+\))?:", re.IGNORECASE)),
    ("perf", re.compile(r"^perf(\(.+\))?:", re.IGNORECASE)),
]


class GitChangelog:
    """Collect and format git commits into changelog sections."""

    def __init__(self, repo_path: str | Path = ".") -> None:
        self.repo_path = Path(repo_path)

    def _run_git(self, *args: str) -> str:
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                return ""
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def _categorize(self, subject: str) -> str:
        for category, pattern in CATEGORY_PATTERNS:
            if pattern.match(subject.strip()):
                return category
        return "other"

    def _parse_log(self, log_output: str) -> list[CommitInfo]:
        commits: list[CommitInfo] = []
        for block in log_output.strip().split("\n\n"):
            lines = block.strip().split("\n")
            if len(lines) < 3:
                continue
            commit_hash = lines[0].removeprefix("commit ").strip()
            author = lines[1].removeprefix("Author: ").strip()
            subject = lines[2].strip()
            commits.append(
                CommitInfo(
                    hash=commit_hash[:8],
                    subject=subject,
                    author=author,
                    category=self._categorize(subject),
                )
            )
        return commits

    def collect(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
        max_count: int = 100,
    ) -> list[CommitInfo]:
        """Collect commits from git log."""
        args = ["log", f"--max-count={max_count}", "--format=commit %H%nAuthor: %an <%ae>%n%s%n"]
        if since:
            args.append(f"--since={since}")
        if until:
            args.append(f"--until={until}")
        output = self._run_git(*args)
        return self._parse_log(output)

    def collect_range(self, from_ref: str, to_ref: str = "HEAD") -> list[CommitInfo]:
        """Collect commits between two git refs."""
        output = self._run_git(
            "log",
            f"{from_ref}..{to_ref}",
            "--format=commit %H%nAuthor: %an <%ae>%n%s%n",
        )
        return self._parse_log(output)

    def format_markdown(
        self,
        commits: list[CommitInfo] | None = None,
        *,
        version: str | None = None,
    ) -> str:
        """Format commits as a Keep a Changelog-style Markdown section."""
        commits = commits if commits is not None else self.collect()
        if not commits:
            return "No commits found."

        grouped: dict[str, list[CommitInfo]] = {}
        for commit in commits:
            grouped.setdefault(commit.category, []).append(commit)

        section_titles = {
            "feat": "Added",
            "fix": "Fixed",
            "docs": "Documentation",
            "refactor": "Changed",
            "perf": "Performance",
            "test": "Tests",
            "chore": "Chore",
            "other": "Other",
        }

        lines: list[str] = []
        if version:
            lines.append(f"## [{version}]")
            lines.append("")

        for category in ["feat", "fix", "perf", "refactor", "docs", "test", "chore", "other"]:
            items = grouped.get(category, [])
            if not items:
                continue
            lines.append(f"### {section_titles[category]}")
            for commit in items:
                lines.append(f"- {commit.subject} ({commit.hash})")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def summary(self, commits: list[CommitInfo] | None = None) -> str:
        """Return a short summary of collected commits."""
        commits = commits if commits is not None else self.collect()
        if not commits:
            return "No commits found."

        by_category: dict[str, int] = {}
        for commit in commits:
            by_category[commit.category] = by_category.get(commit.category, 0) + 1

        lines = [f"Commits: {len(commits)}"]
        for category, count in sorted(by_category.items()):
            lines.append(f"  {category}: {count}")
        return "\n".join(lines)
