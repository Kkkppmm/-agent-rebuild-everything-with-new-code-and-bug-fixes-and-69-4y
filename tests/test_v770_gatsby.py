"""Tests for v7.70.0 GatsbyAnalyzer integration."""

from pathlib import Path

from devai import DevAI, GatsbyAnalyzer
from devai.project_health import ProjectHealth

HARDENED_GATSBY_CONFIG = """\
/** @type {import('gatsby').GatsbyConfig} */
module.exports = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'https://example.com',
  },
  plugins: [],
  trailingSlash: 'never',
};
"""


class TestV770GatsbyIntegration:
    def test_facade_gatsby(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().gatsby(tmp_path)
        assert isinstance(analyzer, GatsbyAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_gatsby_category(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "gatsby" in names

    def test_public_exports(self):
        from devai import GatsbyFinding, GatsbyInfo, GatsbyStats

        assert GatsbyAnalyzer is not None
        assert GatsbyFinding is not None
        assert GatsbyInfo is not None
        assert GatsbyStats is not None
