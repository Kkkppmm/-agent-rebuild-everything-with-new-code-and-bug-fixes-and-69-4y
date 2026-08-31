"""Tests for GatsbyAnalyzer."""

from pathlib import Path

from devai.gatsby_analyzer import GatsbyAnalyzer, GatsbyFinding


INSECURE_GATSBY_CONFIG = """\
const config = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'http://example.com',
  },
  trailingSlash: 'never',
  graphqlPlayground: true,
  plugins: [
    {
      resolve: 'gatsby-plugin-google-analytics',
      options: { trackingId: 'UA-123456789-1' },
    },
    {
      resolve: 'gatsby-source-contentful',
      options: { accessToken: 'hardcoded_contentful_token_abc123' },
    },
  ],
  flags: { DEV_SSR: true, FAST_DEV: true, PRESERVE_WEBPACK_CACHE: true },
  developMiddleware: (app) => {
    app.use('/proxy', require('http-proxy-middleware')({
      target: 'http://10.0.0.1:8080',
    }));
  },
  api_key: 'api_key=hardcoded_secret_value_12345',
};

module.exports = config;
"""

HARDENED_GATSBY_CONFIG = """\
const config = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'https://example.com',
  },
  trailingSlash: 'always',
  plugins: [],
  flags: { DEV_SSR: false, FAST_DEV: false, PRESERVE_WEBPACK_CACHE: false },
};

module.exports = config;
"""


class TestGatsbyAnalyzer:
    def test_detects_insecure_gatsby_config(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(INSECURE_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "site_url_http" in kinds
        assert "graphql_playground" in kinds
        assert "plugin_secret" in kinds
        assert "proxy_internal" in kinds
        assert "dev_ssr_flag" in kinds
        assert "trailing_slash_never" in kinds
        assert "analytics_id_hardcoded" in kinds
        assert "fast_dev_flag" in kinds
        assert "preserve_webpack_cache" in kinds
        assert "develop_middleware" in kinds
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
        assert "siteUrl: 'https://example.com'" in template
        assert "DEV_SSR: false" in template

    def test_detects_gatsby_node_config(self, tmp_path: Path):
        (tmp_path / "gatsby-node.js").write_text(
            "exports.onCreatePage = () => { DANGEROUSLY_DISABLE_ESLINT = true; };\n",
            encoding="utf-8",
        )
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "eslint_disabled" for f in findings)
