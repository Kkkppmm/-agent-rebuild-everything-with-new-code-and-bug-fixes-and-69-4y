"""Tests for GatsbyAnalyzer."""

from pathlib import Path

from devai.gatsby_analyzer import GatsbyAnalyzer, GatsbyFinding


INSECURE_GATSBY_CONFIG = """\
module.exports = {
  siteMetadata: {
    title: 'My Site',
    apiKey: 'api_key=hardcoded_secret_value_12345',
    siteUrl: 'http://internal.example.com',
  },
  trailingSlash: 'always',
  graphqlTypegen: { generateOnBuild: false },
  flags: { DEV_SSR: false, DANGEROUSLY_DISABLE_GRAPHQL_IDE: true },
  proxy: [
    { prefix: '/api', url: 'http://10.0.0.1:8080' },
  ],
  headers: [
  { source: '/(.*)', headers: [{ key: 'Access-Control-Allow-Origin', value: '*' }] },
  ],
  plugins: [
    {
      resolve: 'gatsby-source-contentful',
      options: {
        accessToken: 'hardcoded_contentful_token_12345',
        spaceId: 'abc123',
      },
    },
  ],
  GENERATE_SOURCEMAP: true,
  trackingId: 'UA-12345678-1',
};
"""

HARDENED_GATSBY_CONFIG = """\
module.exports = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'https://example.com',
  },
  trailingSlash: 'never',
  graphqlTypegen: { generateOnBuild: true },
  flags: { DEV_SSR: true },
  plugins: ['gatsby-plugin-react-helmet'],
};
"""


class TestGatsbyAnalyzer:
    def test_detects_insecure_gatsby_config(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(INSECURE_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "proxy_internal" in kinds
        assert "graphql_ide_disabled" in kinds
        assert "cors_wildcard" in kinds
        assert "plugin_secret" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "trailing_slash_always" in kinds
        assert "dev_ssr_disabled" in kinds
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
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = GatsbyFinding(
            kind="test",
            severity="high",
            message="test message",
            path="gatsby-config.js",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Gatsby configuration analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = GatsbyAnalyzer(".").generate_hardened_template()
        assert "trailingSlash: 'never'" in template
        assert "generateOnBuild: true" in template
