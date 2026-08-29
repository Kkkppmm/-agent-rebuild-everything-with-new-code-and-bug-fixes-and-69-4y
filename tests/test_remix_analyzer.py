"""Tests for RemixAnalyzer."""

from pathlib import Path

from devai.remix_analyzer import RemixAnalyzer, RemixFinding


INSECURE_REMIX_CONFIG = """\
/** @type {import('@remix-run/dev').AppConfig} */
export default {
  appDirectory: '../outside-app',
  assetsBuildDirectory: 'public/build',
  publicPath: 'http://cdn.example.com/build/',
  serverBuildPath: '../build/index.js',
  serverModuleFormat: 'esm',
  serverMinify: false,
  serverDependenciesToBundle: 'all',
  devServerHost: '0.0.0.0',
  liveReload: true,
  ignoredRouteFiles: ['**'],
  watchPaths: ['..', '*'],
  SESSION_SECRET: 'hardcoded_session_secret_value',
  future: {
    v2_dev: true,
    unstable_tailwind: true,
  },
  tls: {
    rejectUnauthorized: false,
  },
  proxy: {
  '/api': { target: 'http://10.0.0.1:8080' },
  },
  sourcemap: true,
  cors: '*',
  api_key: 'api_key=hardcoded_secret_value_12345',
};
"""

HARDENED_REMIX_CONFIG = """\
/** @type {import('@remix-run/dev').AppConfig} */
export default {
  appDirectory: 'app',
  assetsBuildDirectory: 'public/build',
  publicPath: '/build/',
  serverBuildPath: 'build/index.js',
  serverModuleFormat: 'esm',
  serverMinify: true,
  ignoredRouteFiles: ['**/.*'],
  watchPaths: ['.'],
  future: {},
};
"""


class TestRemixAnalyzer:
    def test_detects_insecure_remix_config(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(INSECURE_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "path_traversal" in kinds
        assert "insecure_http" in kinds
        assert "host_exposed" in kinds
        assert "tls_verification_disabled" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "server_deps_bundle_all" in kinds
        assert "server_minify_disabled" in kinds
        assert "proxy_internal" in kinds
        assert analyzer.stats.configs == 1
        assert analyzer.stats.findings > 0
        assert analyzer.health_score() < 50.0

    def test_hardened_remix_config_scores_well(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = RemixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(
            "export default { SESSION_SECRET: 'leaked_secret_value' };\n",
            encoding="utf-8",
        )
        analyzer = RemixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        finding = findings[0]
        assert isinstance(finding, RemixFinding)
        assert finding.severity in ("high", "medium", "low")
        assert "remix.config.js" in finding.format()

    def test_generate_hardened_template(self):
        template = RemixAnalyzer(".").generate_hardened_template()
        assert "appDirectory" in template
        assert "serverMinify: true" in template
        assert "RemixAnalyzer" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "remix.config.ts").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Remix configuration analysis" in context
        assert "remix.config.ts" in context
        assert "health score" in context

    def test_typescript_config_detected(self, tmp_path: Path):
        (tmp_path / "remix.config.ts").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        configs = analyzer.configs()
        assert len(configs) == 1
        assert configs[0].name == "remix.config.ts"
