"""GitChangelog — generate Keep a Changelog-style release notes from git history."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


_CHANGELOG_CATEGORIES = {
    "feat": "Added",
    "fix": "Fixed",
    "docs": "Documentation",
    "refactor": "Changed",
    "perf": "Performance",
    "test": "Tests",
    "chore": "Chore",
    "ci": "CI",
    "build": "Build",
    "style": "Style",
}


@dataclass
class ChangelogEntry:
    """A single changelog entry parsed from a commit message."""

    hash: str
    category: str
    message: str
    author: str = ""

    def formatted(self) -> str:
        return f"- {self.message} ({self.hash[:8]})"


@dataclass
class GitChangelog:
    """Generate Keep a Changelog-style release notes from git commit history.

    GitChangelog parses conventional commit messages and groups them into
  changelog sections for release automation.
    """

    repo_path: Path
    _entries: list[ChangelogEntry] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self.repo_path = Path(self.repo_path).resolve()

    def collect(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
        max_commits: int = 200,
    ) -> list[ChangelogEntry]:
        """Collect changelog entries from git log."""
        self._entries.clear()

        cmd = [
            "git",
            "-C",
            str(self.repo_path),
            "log",
            f"--max-count={max_commits}",
            "--pretty=format:%H|%an|%s",
        ]
        if since:
            cmd.append(since)
        if until:
            cmd.insert(-1, until)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        except (subprocess.SubprocessError, FileNotFoundError):
            return []

        if result.returncode != 0:
            return []

        for line in result.stdout.strip().splitlines():
            parts = line.split("|", 2)
            if len(parts) < 3:
                continue
            hash_, author, subject = parts
            category, message = self._parse_subject(subject)
            self._entries.append(
                ChangelogEntry(hash=hash_, category=category, message=message, author=author)
            )

        return list(self._entries)

    def generate(
        self,
        version: str,
        *,
        since: str | None = None,
        date: str | None = None,
    ) -> str:
        """Generate a markdown changelog section for a release."""
        if not self._entries:
            self.collect(since=since)

        from datetime import date as date_cls

        release_date = date or date_cls.today().isoformat()
        lines = [f"## [{version}] - {release_date}", ""]
        grouped: dict[str, list[ChangelogEntry]] = {}

        for entry in self._entries:
            section = _CHANGELOG_CATEGORIES.get(entry.category, "Other")
            grouped.setdefault(section, []).append(entry)

        for section in sorted(grouped.keys()):
            lines.append(f"### {section}")
            lines.append("")
            for entry in grouped[section]:
                lines.append(entry.formatted())
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def summary(self) -> dict[str, int | list[str]]:
        """Return a summary of collected entries by category."""
        if not self._entries:
            self.collect()
        counts: dict[str, int] = {}
        for entry in self._entries:
            counts[entry.category] = counts.get(entry.category, 0) + 1
        return {
            "total": len(self._entries),
            "by_category": counts,
            "categories": sorted(counts.keys()),
        }

    @staticmethod
    def _parse_subject(subject: str) -> tuple[str, str]:
        match = re.match(r"^(\w+)(?:\([^)]+\))?!?:\s*(.+)$", subject)
        if match:
            return match.group(1).lower(), match.group(2).strip()
        return "other", subject.strip()
