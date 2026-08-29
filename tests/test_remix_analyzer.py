"""Tests for RemixAnalyzer."""

from pathlib import Path

from devai.remix_analyzer import RemixAnalyzer, RemixFinding


INSECURE_REMIX_CONFIG = """\
export default {
  publicPath: 'http://example.com/build/',
  sessionSecret: 'super_secret_session_key_12345',
  future: { v2_dev: true },
  serverDependenciesToBundle: false,
  vite: {
    server: {
      host: '0.0.0.0',
      cors: true,
      fs: { allow: ['..', '*'] },
    },
    build: { sourcemap: true },
  },
  devProxy: {
    '/api': { target: 'http://192.168.1.1/admin', rejectUnauthorized: false },
  },
  watchPaths: ['*'],
};
"""

HARDENED_REMIX_CONFIG = """\
export default {
  publicPath: '/build/',
  serverModuleFormat: 'esm',
  serverDependenciesToBundle: 'all',
  future: { v2_dev: false },
  vite: {
    server: { host: '127.0.0.1', fs: { allow: ['.'] }, cors: false },
    build: { sourcemap: false },
  },
};
"""


class TestRemixAnalyzer:
    def test_detects_insecure_remix_config(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(INSECURE_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "public_path_http" in kinds
        assert "host_exposed" in kinds
        assert "cors_open" in kinds
        assert "fs_allow_permissive" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "proxy_internal" in kinds
        assert "v2_dev_enabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_remix_config_scores_well(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = RemixAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = RemixFinding(
            kind="test",
            severity="high",
            message="test message",
            path="remix.config.js",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Remix configuration analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = RemixAnalyzer(".").generate_hardened_template()
        assert "serverDependenciesToBundle" in template
        assert "sourcemap: false" in template
