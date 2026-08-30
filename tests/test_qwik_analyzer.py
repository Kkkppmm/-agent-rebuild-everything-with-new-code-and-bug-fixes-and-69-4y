"""Tests for QwikAnalyzer."""

from pathlib import Path

from devai.qwik_analyzer import QwikAnalyzer, QwikFinding


INSECURE_QWIK_CONFIG = """\
import { defineConfig } from 'vite';
import { qwikVite } from '@builder.io/qwik/optimizer';
import { qwikCity } from '@builder.io/qwik-city/vite';

export default defineConfig({
  plugins: [
    qwikCity({ trailingSlash: false }),
    qwikVite(),
  ],
  server: {
    host: '0.0.0.0',
    port: 5173,
    cors: true,
    fs: { allow: ['..', '*'] },
    proxy: { '/api': { target: 'http://10.0.0.1:8080' } },
  },
  build: { sourcemap: true },
  env: { API_KEY: 'api_key=hardcoded_secret_value_12345' },
  api_key: 'api_key=hardcoded_secret_value_12345',
});
"""

HARDENED_QWIK_CONFIG = """\
import { defineConfig } from 'vite';
import { qwikVite } from '@builder.io/qwik/optimizer';
import { qwikCity } from '@builder.io/qwik-city/vite';

export default defineConfig({
  plugins: [
    qwikCity({ trailingSlash: true }),
    qwikVite(),
  ],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    fs: { allow: ['.'] },
    cors: false,
  },
  build: { sourcemap: false },
});
"""


class TestQwikAnalyzer:
    def test_detects_insecure_qwik_config(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(INSECURE_QWIK_CONFIG, encoding="utf-8")
        analyzer = QwikAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "host_exposed" in kinds
        assert "cors_open" in kinds
        assert "fs_allow_permissive" in kinds
        assert "proxy_internal" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "env_secret" in kinds
        assert "trailing_slash_false" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_qwik_config_scores_well(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(HARDENED_QWIK_CONFIG, encoding="utf-8")
        analyzer = QwikAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = QwikAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = QwikFinding(
            kind="test",
            severity="high",
            message="test message",
            path="vite.config.ts",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(HARDENED_QWIK_CONFIG, encoding="utf-8")
        analyzer = QwikAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Qwik City configuration analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = QwikAnalyzer(".").generate_hardened_template()
        assert "qwikCity" in template
        assert "sourcemap: false" in template

    def test_ignores_non_qwik_vite_config(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(
            "export default { server: { host: '0.0.0.0' } };\n",
            encoding="utf-8",
        )
        analyzer = QwikAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
