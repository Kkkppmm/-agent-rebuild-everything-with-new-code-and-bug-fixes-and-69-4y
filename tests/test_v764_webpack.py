"""Tests for v7.64.0 WebpackAnalyzer integration."""

from pathlib import Path

from devai import DevAI, WebpackAnalyzer
from devai.project_health import ProjectHealth

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


class TestV764WebpackIntegration:
    def test_facade_webpack(self, tmp_path: Path):
        (tmp_path / "webpack.config.js").write_text(HARDENED_WEBPACK_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().webpack(tmp_path)
        assert isinstance(analyzer, WebpackAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_webpack_category(self, tmp_path: Path):
        (tmp_path / "webpack.config.js").write_text(HARDENED_WEBPACK_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "webpack" in names

    def test_public_exports(self):
        from devai import WebpackFinding, WebpackInfo, WebpackStats

        assert WebpackAnalyzer is not None
        assert WebpackFinding is not None
        assert WebpackInfo is not None
        assert WebpackStats is not None
