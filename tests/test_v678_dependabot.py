"""Tests for v6.78.0 DependabotAnalyzer integration."""

from pathlib import Path

from devai import DependabotAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    groups:
      security-updates:
        applies-to: security-updates
        patterns:
          - "*"
    reviewers:
      - "security-team"
"""


class TestV678DependabotAnalyzer:
    def test_facade_dependabot(self, tmp_path: Path):
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        (github_dir / "dependabot.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().dependabot(tmp_path)
        assert isinstance(analyzer, DependabotAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_dependabot_category(self, tmp_path: Path):
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        (github_dir / "dependabot.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "dependabot" in names
