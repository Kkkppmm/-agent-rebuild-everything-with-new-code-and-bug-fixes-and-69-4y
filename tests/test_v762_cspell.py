"""Tests for v7.62.0 CspellAnalyzer integration."""

from pathlib import Path

from devai import CspellAnalyzer, DevAI
from devai.project_health import ProjectHealth

HARDENED_CONFIG = """\
{
  "version": "0.2",
  "enabled": true,
  "minWordLength": 4,
  "ignorePaths": ["node_modules"]
}
"""


class TestV762CspellIntegration:
    def test_facade_cspell(self, tmp_path: Path):
        (tmp_path / "cspell.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().cspell(tmp_path)
        assert isinstance(analyzer, CspellAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_cspell_category(self, tmp_path: Path):
        (tmp_path / "cspell.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "cspell" in names

    def test_public_exports(self):
        from devai import CspellFinding, CspellInfo, CspellStats

        assert CspellAnalyzer is not None
        assert CspellFinding is not None
        assert CspellInfo is not None
        assert CspellStats is not None
