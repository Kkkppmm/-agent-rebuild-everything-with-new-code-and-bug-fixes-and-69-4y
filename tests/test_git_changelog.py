"""Tests for DevAI GitChangelog."""

import subprocess
from pathlib import Path

from devai.git_changelog import GitChangelog, CommitInfo


class TestGitChangelog:
    def _init_repo(self, tmp_path: Path) -> Path:
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test User"],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )
        (tmp_path / "README.md").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "feat: initial commit"],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "commit", "--allow-empty", "-m", "fix: patch release"],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )
        return tmp_path

    def test_collect_commits(self, tmp_path: Path):
        repo = self._init_repo(tmp_path)
        changelog = GitChangelog(repo)
        commits = changelog.collect()
        assert len(commits) >= 2
        categories = {c.category for c in commits}
        assert "feat" in categories
        assert "fix" in categories

    def test_format_markdown(self, tmp_path: Path):
        repo = self._init_repo(tmp_path)
        changelog = GitChangelog(repo)
        commits = changelog.collect()
        md = changelog.format_markdown(commits, version="1.0.0")
        assert "## [1.0.0]" in md
        assert "feat: initial commit" in md

    def test_categorize_commit(self):
        changelog = GitChangelog(".")
        assert changelog._categorize("feat: add feature") == "feat"
        assert changelog._categorize("fix: bug") == "fix"
        assert changelog._categorize("misc change") == "other"

    def test_summary(self, tmp_path: Path):
        repo = self._init_repo(tmp_path)
        changelog = GitChangelog(repo)
        summary = changelog.summary()
        assert "Commits:" in summary
