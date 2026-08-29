"""Tests for RemixAnalyzer."""

from pathlib import Path

from devai.remix_analyzer import RemixAnalyzer


INSECURE_REMIX_CONFIG = """\
export default {
  publicPath: 'http://example.com/build/',
  basename: 'http://example.com',
  dev: { host: '0.0.0.0', port: 3000 },
  watchPaths: ['..', '*'],
  serverBuildPath: '/tmp/server',
  api_key: 'api_key=hardcoded_secret_value_12345',
  proxy: { target: 'http://192.168.1.1/admin' },
  build: { sourcemap: true },
};
"""

HARDENED_REMIX_CONFIG = """\
export default {
  serverBuildPath: 'build/server',
  publicPath: 'https://example.com/build/',
  dev: { host: '127.0.0.1', port: 3000 },
  watchPaths: ['.'],
};
"""


class TestRemixAnalyzer:
    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = RemixAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(INSECURE_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) > 0
        assert analyzer.stats.high_severity > 0
        assert analyzer.health_score() < 100.0

    def test_hardened_config_clean(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_generate_hardened_template(self):
        template = RemixAnalyzer(".").generate_hardened_template()
        assert "127.0.0.1" in template
        assert "serverBuildPath" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        assert "Remix:" in analyzer.summary()
        assert "health score" in analyzer.to_context()
