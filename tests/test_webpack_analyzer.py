"""Tests for WebpackAnalyzer."""

from pathlib import Path

from devai.webpack_analyzer import WebpackAnalyzer, WebpackFinding


INSECURE_WEBPACK_CONFIG = """\
const path = require('path');
const webpack = require('webpack');

module.exports = {
  mode: 'development',
  devtool: 'source-map',
  output: {
    publicPath: 'https://cdn.example.com/assets/',
    path: path.resolve(__dirname, 'dist'),
  },
  devServer: {
    host: '0.0.0.0',
    allowedHosts: 'all',
    disableHostCheck: true,
    writeToDisk: true,
    static: { directory: '..' },
    proxy: {
      '/api': { target: 'http://10.0.0.1:8080' },
    },
    https: { rejectUnauthorized: false },
    headers: { 'Access-Control-Allow-Origin': '*' },
  },
  optimization: {
    minimize: false,
  },
  plugins: [
    new webpack.DefinePlugin({
      API_KEY: JSON.stringify('api_key=hardcoded_secret_value_12345'),
    }),
    new ExposeWebpackPlugin('secret'),
  ],
  resolve: {
    fallback: { '*': require.resolve('stream-browserify') },
  },
  api_key: 'api_key=hardcoded_secret_value_12345',
};
"""

HARDENED_WEBPACK_CONFIG = """\
const path = require('path');

module.exports = {
  mode: 'production',
  devtool: false,
  output: {
    publicPath: '/',
    path: path.resolve(__dirname, 'dist'),
  },
  devServer: {
    host: 'localhost',
    allowedHosts: ['localhost'],
    static: { directory: path.join(__dirname, 'public') },
  },
  optimization: {
    minimize: true,
  },
};
"""


class TestWebpackAnalyzer:
    def test_detects_insecure_webpack_config(self, tmp_path: Path):
        (tmp_path / "webpack.config.js").write_text(INSECURE_WEBPACK_CONFIG, encoding="utf-8")
        analyzer = WebpackAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "host_exposed" in kinds
        assert "allowed_hosts_all" in kinds
        assert "disable_host_check" in kinds
        assert "cors_open" in kinds
        assert "proxy_internal" in kinds
        assert "reject_unauthorized_false" in kinds
        assert "sourcemap_enabled" in kinds
        assert "minimize_disabled" in kinds
        assert "define_secret" in kinds
        assert "expose_loader" in kinds
        assert "polyfill_wildcard" in kinds
        assert "write_to_disk" in kinds
        assert "public_path_absolute" in kinds
        assert "mode_development" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_webpack_config_scores_well(self, tmp_path: Path):
        (tmp_path / "webpack.config.js").write_text(HARDENED_WEBPACK_CONFIG, encoding="utf-8")
        analyzer = WebpackAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].has_dev_server is True
        assert analyzer.infos[0].has_optimization is True
        assert analyzer.infos[0].mode == "production"

    def test_finds_webpack_config_variants(self, tmp_path: Path):
        (tmp_path / "webpack.config.ts").write_text(HARDENED_WEBPACK_CONFIG, encoding="utf-8")
        (tmp_path / "webpack.prod.js").write_text(HARDENED_WEBPACK_CONFIG, encoding="utf-8")
        analyzer = WebpackAnalyzer(str(tmp_path))
        assert len(analyzer.configs()) == 2

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = WebpackAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.configs == 0

    def test_finding_format(self):
        finding = WebpackFinding(
            kind="host_exposed",
            severity="medium",
            message="dev server bound to all interfaces",
            path="webpack.config.js",
            lineno=10,
            line="    host: '0.0.0.0',",
        )
        formatted = finding.format()
        assert "[medium]" in formatted
        assert "webpack.config.js:10" in formatted

    def test_generate_hardened_template(self):
        analyzer = WebpackAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "mode: 'production'" in template
        assert "host: 'localhost'" in template
        assert "minimize: true" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "webpack.config.js").write_text(HARDENED_WEBPACK_CONFIG, encoding="utf-8")
        analyzer = WebpackAnalyzer(str(tmp_path))
        assert "1 config(s)" in analyzer.summary()
        context = analyzer.to_context()
        assert "Webpack configuration analysis" in context
        assert "health score" in context
