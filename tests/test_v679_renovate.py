"""Tests for v6.79.0 RenovateAnalyzer integration."""

from pathlib import Path

from devai import DevAI, RenovateAnalyzer
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """\
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "vulnerabilityAlerts": {
    "enabled": true
  },
  "schedule": ["before 6am on monday"],
  "packageRules": [
    {
      "matchManagers": ["pip"],
      "groupName": "python dependencies"
    }
  ]
}
"""

UNSAFE_CONFIG = """\
{
  "automerge": true,
  "vulnerabilityAlerts": false,
  "hostRules": [
    {
      "matchHost": "registry.example.com",
      "token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    }
  ],
  "postUpgradeTasks": {
    "commands": ["npm install", "npm test"]
  }
}
"""


class TestRenovateAnalyzer:
    def test_finds_no_issues_in_hardened_config(self, tmp_path: Path):
        (tmp_path / "renovate.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = RenovateAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1

    def test_detects_unsafe_settings(self, tmp_path: Path):
        (tmp_path / "renovate.json").write_text(UNSAFE_CONFIG, encoding="utf-8")
        analyzer = RenovateAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "hardcoded_secret" in kinds
        assert "vulnerability_alerts_disabled" in kinds
        assert "post_upgrade_commands" in kinds

    def test_facade_renovate(self, tmp_path: Path):
        (tmp_path / "renovate.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().renovate(tmp_path)
        assert isinstance(analyzer, RenovateAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_renovate_category(self, tmp_path: Path):
        (tmp_path / "renovate.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "renovate" in names

    def test_generate_hardened_template(self):
        template = RenovateAnalyzer(".").generate_hardened_template()
        assert "vulnerabilityAlerts" in template
        assert "packageRules" in template

    def test_github_renovate_path(self, tmp_path: Path):
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        (github_dir / "renovate.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = RenovateAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
