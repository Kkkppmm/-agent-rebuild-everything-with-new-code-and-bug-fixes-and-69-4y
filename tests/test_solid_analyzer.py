"""Tests for SolidAnalyzer."""

from pathlib import Path

from devai.solid_analyzer import SolidAnalyzer, SolidFinding


INSECURE_APP_CONFIG = """\
import { defineConfig } from '@solidjs/start/config';

export default defineConfig({
  server: {
    preset: 'node',
    host: '0.0.0.0',
    port: 3000,
    trustProxy: 'all',
  },
  ssr: false,
  csp: false,
  middleware: {
    secret: 'session_secret=hardcoded_secret_value_12345',
  },
  vite: {
    server: {
      host: '0.0.0.0',
      port: 5173,
      cors: true,
      allowedHosts: 'all',
      fs: { allow: ['..', '*'] },
      proxy: { '/api': { target: 'http://10.0.0.1:8080' } },
    },
    build: { sourcemap: true },
    env: { SESSION_SECRET: 'session_secret=hardcoded_secret_value_12345' },
  },
  vinxi: {
    publicDir: '../secrets',
  },
});
"""

INSECURE_VITE_CONFIG = """\
import { defineConfig } from 'vite';
import solid from 'vite-plugin-solid';

export default defineConfig({
  plugins: [solid()],
  server: {
    host: '0.0.0.0',
    cors: true,
    proxy: { '/api': { target: 'http://192.168.1.1:8080' } },
  },
  build: { sourcemap: true },
});
"""

HARDENED_APP_CONFIG = """\
import { defineConfig } from '@solidjs/start/config';

export default defineConfig({
  server: {
    preset: 'node-server',
    host: '127.0.0.1',
    port: 3000,
    strictPort: true,
  },
  ssr: true,
  middleware: './src/middleware.ts',
  vite: {
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      fs: { allow: ['.'] },
      cors: false,
    },
    build: { sourcemap: false },
  },
});
"""


class TestSolidAnalyzer:
    def test_detects_insecure_solidstart_app_config(self, tmp_path: Path):
        (tmp_path / "app.config.ts").write_text(INSECURE_APP_CONFIG, encoding="utf-8")
        analyzer = SolidAnalyzer(str(tmp_path))
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
        assert "csp_disabled" in kinds
        assert "public_dir_parent" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_vite_solid_config(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(INSECURE_VITE_CONFIG, encoding="utf-8")
        analyzer = SolidAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "host_exposed" in kinds
        assert "cors_open" in kinds
        assert "proxy_internal" in kinds
        assert "sourcemaps_enabled" in kinds

    def test_hardened_solid_config_scores_well(self, tmp_path: Path):
        (tmp_path / "app.config.ts").write_text(HARDENED_APP_CONFIG, encoding="utf-8")
        analyzer = SolidAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = SolidAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = SolidFinding(
            kind="test",
            severity="high",
            message="test message",
            path="app.config.ts",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "app.config.ts").write_text(HARDENED_APP_CONFIG, encoding="utf-8")
        analyzer = SolidAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "SolidJS configuration analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = SolidAnalyzer(".").generate_hardened_template()
        assert "@solidjs/start/config" in template
        assert "sourcemap: false" in template

    def test_ignores_non_solid_vite_config(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(
            "export default { server: { host: '0.0.0.0' } };\n",
            encoding="utf-8",
        )
        analyzer = SolidAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
