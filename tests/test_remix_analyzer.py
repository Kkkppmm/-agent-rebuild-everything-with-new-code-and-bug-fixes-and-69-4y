"""Tests for RemixAnalyzer."""

from pathlib import Path

from devai.remix_analyzer import RemixAnalyzer, RemixFinding


INSECURE_REMIX_CONFIG = """\
import { vitePlugin as remix } from '@remix-run/dev';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [remix()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    cors: true,
    allowedHosts: 'all',
    fs: { allow: ['..', '*'] },
    proxy: { '/api': { target: 'http://10.0.0.1:8080' } },
  },
  build: { sourcemap: true },
  ssr: false,
  env: { SESSION_SECRET: 'session_secret=hardcoded_secret_value_12345' },
  session_secret: 'session_secret=hardcoded_secret_value_12345',
});
"""

INSECURE_REMIX_LEGACY_CONFIG = """\
/** @type {import('@remix-run/dev').AppConfig} */
module.exports = {
  publicPath: 'http://example.com/build/',
  watchPaths: ['../secrets'],
  serverBuildPath: '../dist/server',
  ignoredRouteFiles: ['**/*'],
};
"""

HARDENED_REMIX_CONFIG = """\
import { vitePlugin as remix } from '@remix-run/dev';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [
    remix({
      ignoredRouteFiles: ['**/.*'],
      future: {
        v3_fetcherPersist: true,
        v3_relativeSplatPath: true,
        v3_throwAbortReason: true,
      },
    }),
  ],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    fs: { allow: ['.'] },
    cors: false,
  },
  build: { sourcemap: false },
  ssr: true,
});
"""


class TestRemixAnalyzer:
    def test_detects_insecure_remix_vite_config(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(INSECURE_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "host_exposed" in kinds
        assert "cors_open" in kinds
        assert "allowed_hosts_all" in kinds
        assert "fs_allow_permissive" in kinds
        assert "proxy_internal" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "env_secret" in kinds
        assert "ssr_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_remix_legacy_config(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(
            INSECURE_REMIX_LEGACY_CONFIG, encoding="utf-8"
        )
        analyzer = RemixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "public_path_http" in kinds
        assert "watch_paths_parent" in kinds
        assert "server_build_outside" in kinds

    def test_hardened_remix_config_scores_well(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
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
            path="vite.config.ts",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
        analyzer = RemixAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Remix configuration analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = RemixAnalyzer(".").generate_hardened_template()
        assert "remix" in template
        assert "sourcemap: false" in template

    def test_ignores_non_remix_vite_config(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(
            "export default { server: { host: '0.0.0.0' } };\n",
            encoding="utf-8",
        )
        analyzer = RemixAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
