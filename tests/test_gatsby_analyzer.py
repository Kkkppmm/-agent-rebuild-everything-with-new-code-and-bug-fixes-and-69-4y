"""Tests for GatsbyAnalyzer."""

from pathlib import Path

from devai.gatsby_analyzer import GatsbyAnalyzer, GatsbyFinding


INSECURE_GATSBY_CONFIG = """\
module.exports = {
  siteMetadata: {
    siteUrl: 'http://example.com',
    apiKey: 'hardcoded_gatsby_api_key_12345',
  },
  plugins: [
    {
      resolve: 'gatsby-source-contentful',
      options: {
        accessToken: 'hardcoded_contentful_token',
        spaceId: 'abc123',
      },
    },
  ],
  proxy: [
    { prefix: '/api', url: 'http://192.168.1.1:8080' },
  ],
  graphqlPlayground: true,
  trailingSlash: 'always',
};
"""

HARDENED_GATSBY_CONFIG = """\
module.exports = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'https://example.com',
  },
  plugins: [],
};
"""


class TestGatsbyAnalyzer:
    def test_detects_insecure_gatsby_config(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(INSECURE_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "site_url_http" in kinds
        assert "site_metadata_secret" in kinds
        assert "plugin_secret" in kinds
        assert "proxy_internal" in kinds
        assert "graphql_playground" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_gatsby_config_scores_well(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = GatsbyAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = GatsbyFinding(
            kind="test",
            severity="high",
            message="test message",
            path="gatsby-config.js",
            lineno=1,
        )
        assert "[high]" in finding.format()

    def test_generate_hardened_template(self):
        template = GatsbyAnalyzer(".").generate_hardened_template()
        assert "siteUrl: 'https://example.com'" in template
