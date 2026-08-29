"""Tests for GatsbyAnalyzer."""

from pathlib import Path

from devai.gatsby_analyzer import GatsbyAnalyzer, GatsbyFinding


INSECURE_GATSBY_CONFIG = """\
module.exports = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'http://example.com',
    apiKey: 'hardcoded_api_key_12345',
  },
  plugins: [
    {
      resolve: 'gatsby-source-contentful',
      options: {
        accessToken: 'contentful_access_token_secret',
        spaceId: 'space123',
      },
    },
    {
      resolve: 'gatsby-plugin-proxy',
      options: {
        proxy: {
          '/api': { target: 'http://192.168.1.1/admin' },
        },
      },
    },
  ],
  headers: [
    {
      source: '/*',
      headers: [
        { key: 'Access-Control-Allow-Origin', value: '*' },
        { key: 'Content-Security-Policy', value: 'none' },
      ],
    },
  ],
  graphqlPlayground: true,
  flags: {
    FAST_DEV: true,
    DEV_SSR: true,
  },
  trailingSlash: 'always',
  mapping: {
    password: 'mapping_password_secret',
  },
  api_key: 'api_key=hardcoded_secret_value_12345',
};
"""

HARDENED_GATSBY_CONFIG = """\
const config = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'https://example.com',
    description: 'A secure Gatsby site',
  },
  plugins: [],
  headers: [
    {
      source: '/*',
      headers: [
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
      ],
    },
  ],
  graphqlTypegen: true,
  trailingSlash: 'never',
};

module.exports = config;
"""


INSECURE_GATSBY_NODE = """\
exports.onCreateDevServer = ({ app }) => {
  app.use('/internal', (req, res) => {
    fetch('http://10.0.0.1:8080/admin');
    res.send('ok');
  });
};

exports.developMiddleware = (app) => {
  app.get('/debug', (req, res) => res.json({ secret: 'leaked' }));
};
"""


class TestGatsbyAnalyzer:
    def test_detects_insecure_gatsby_config(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(INSECURE_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "site_url_http" in kinds
        assert "site_metadata_secret" in kinds
        assert "plugin_secret" in kinds
        assert "proxy_internal" in kinds
        assert "graphql_playground" in kinds
        assert "cors_wildcard" in kinds
        assert "csp_disabled" in kinds
        assert "mapping_credential" in kinds
        assert "fast_dev_flag" in kinds
        assert "dev_ssr_flag" in kinds
        assert "trailing_slash_always" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_gatsby_config_scores_well(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_detects_gatsby_node_issues(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        (tmp_path / "gatsby-node.js").write_text(INSECURE_GATSBY_NODE, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "fetch_internal" in kinds
        assert "develop_middleware" in kinds

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
        assert "X-Frame-Options" in template
