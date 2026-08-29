"""Tests for GatsbyAnalyzer."""

from pathlib import Path

from devai.gatsby_analyzer import GatsbyAnalyzer, GatsbyFinding


INSECURE_GATSBY_CONFIG = """\
/** @type {import('gatsby').GatsbyConfig} */
module.exports = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'http://insecure.example.com',
  },
  pathPrefix: '../outside',
  assetPrefix: 'http://cdn.example.com/assets/',
  plugins: [
    {
      resolve: 'gatsby-source-wordpress',
      options: {
        url: 'http://10.0.0.1/wp-json',
        auth: {
          username: 'admin',
          password: 'hardcoded_password_value',
        },
        accessToken: 'hardcoded_access_token_value',
      },
    },
  ],
  developMiddleware: (app) => {
    app.use('/proxy', require('http-proxy-middleware')({
      target: 'http://192.168.1.1:8080',
    }));
  },
  proxy: {
    '/api': { target: 'http://169.254.169.254' },
  },
  headers: [
    {
      source: '/*',
      headers: [{ key: 'Access-Control-Allow-Origin', value: '*' }],
    },
  ],
  flags: {
    FAST_DEV: true,
    DEV_SSR: true,
  },
  trailingSlash: 'always',
  graphqlPlayground: true,
  host: '0.0.0.0',
  DANGEROUSLY_DISABLE_HOST_CHECK: true,
  GENERATE_SOURCEMAP: true,
  tls: { rejectUnauthorized: false },
  api_key: 'api_key=hardcoded_secret_value_12345',
};
"""

HARDENED_GATSBY_CONFIG = """\
/** @type {import('gatsby').GatsbyConfig} */
module.exports = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'https://example.com',
  },
  plugins: [],
  trailingSlash: 'never',
  headers: [
    {
      source: '/*',
      headers: [
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
      ],
    },
  ],
};
"""


class TestGatsbyAnalyzer:
    def test_detects_insecure_gatsby_config(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(INSECURE_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "path_traversal" in kinds
        assert "insecure_http" in kinds
        assert "host_exposed" in kinds
        assert "host_check_disabled" in kinds
        assert "tls_verification_disabled" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "plugin_credential" in kinds
        assert "proxy_internal" in kinds
        assert "develop_middleware" in kinds
        assert analyzer.stats.configs == 1
        assert analyzer.stats.findings > 0
        assert analyzer.health_score() < 50.0

    def test_hardened_gatsby_config_scores_well(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(
            "module.exports = { accessToken: 'leaked_secret_value' };\n",
            encoding="utf-8",
        )
        analyzer = GatsbyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        finding = findings[0]
        assert isinstance(finding, GatsbyFinding)
        assert finding.severity in ("high", "medium", "low")
        assert "gatsby-config.js" in finding.format()

    def test_generate_hardened_template(self):
        template = GatsbyAnalyzer(".").generate_hardened_template()
        assert "siteMetadata" in template
        assert "trailingSlash" in template
        assert "GatsbyAnalyzer" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "gatsby-config.ts").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Gatsby configuration analysis" in context
        assert "gatsby-config.ts" in context
        assert "health score" in context

    def test_typescript_config_detected(self, tmp_path: Path):
        (tmp_path / "gatsby-config.ts").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        analyzer = GatsbyAnalyzer(str(tmp_path))
        configs = analyzer.configs()
        assert len(configs) == 1
        assert configs[0].name == "gatsby-config.ts"

    def test_gatsby_node_detected(self, tmp_path: Path):
        (tmp_path / "gatsby-node.js").write_text(
            "exports.onCreatePage = () => {};\n",
            encoding="utf-8",
        )
        analyzer = GatsbyAnalyzer(str(tmp_path))
        configs = analyzer.configs()
        assert len(configs) == 1
        assert configs[0].name == "gatsby-node.js"
