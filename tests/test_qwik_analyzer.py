"""Tests for QwikAnalyzer."""

from pathlib import Path

from devai.qwik_analyzer import QwikAnalyzer, QwikFinding


INSECURE_QWIK_VITE_CONFIG = """\
import { defineConfig } from 'vite';
import { qwikCity } from '@builder.io/qwik-city/vite';
import { qwikVite } from '@builder.io/qwik/optimizer';

export default defineConfig({
  plugins: [qwikCity(), qwikVite()],
  devTools: { enabled: true },
  define: {
    API_SECRET: 'super_secret_api_key_12345',
  },
  server: {
    host: '0.0.0.0',
    cors: true,
    origin: '*',
    fs: { allow: ['..', '*'] },
    proxy: {
      '/api': { target: 'http://10.0.0.1:8080', rejectUnauthorized: false },
    },
  },
  preview: {
    host: '0.0.0.0',
    cors: true,
  },
  build: {
    sourcemap: true,
  },
  env: {
    PUBLIC_API_KEY: 'public_secret_key_12345',
  },
  api_key: 'api_key=hardcoded_secret_value_12345',
});
"""

HARDENED_QWIK_VITE_CONFIG = """\
import { defineConfig } from 'vite';
import { qwikCity } from '@builder.io/qwik-city/vite';
import { qwikVite } from '@builder.io/qwik/optimizer';

export default defineConfig({
  plugins: [qwikCity(), qwikVite()],
  server: {
    host: '127.0.0.1',
    cors: false,
    origin: 'https://localhost:5173',
    fs: { allow: ['.'] },
  },
  preview: {
    host: '127.0.0.1',
    cors: false,
  },
  build: {
    sourcemap: false,
  },
  devTools: { enabled: false },
});
"""


def _write_qwik_project(tmp_path: Path, config_text: str) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@builder.io/qwik": "1.0.0", "@builder.io/qwik-city": "1.0.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "vite.config.ts").write_text(config_text, encoding="utf-8")


class TestQwikAnalyzer:
    def test_detects_insecure_qwik_config(self, tmp_path: Path):
        _write_qwik_project(tmp_path, INSECURE_QWIK_VITE_CONFIG)
        analyzer = QwikAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "define_secret" in kinds
        assert "public_env_secret" in kinds
        assert "devtools_enabled" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "cors_open" in kinds
        assert "host_exposed" in kinds
        assert "origin_wildcard" in kinds
        assert "fs_allow_permissive" in kinds
        assert "proxy_internal" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_qwik_config_scores_well(self, tmp_path: Path):
        _write_qwik_project(tmp_path, HARDENED_QWIK_VITE_CONFIG)
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
        _write_qwik_project(tmp_path, HARDENED_QWIK_VITE_CONFIG)
        analyzer = QwikAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Qwik configuration analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = QwikAnalyzer(".").generate_hardened_template()
        assert "devTools: { enabled: false }" in template
        assert "host: '127.0.0.1'" in template

    def test_detects_qwik_config_file(self, tmp_path: Path):
        (tmp_path / "qwik.config.ts").write_text(
            "export default { devTools: true, csrf: false };\n",
            encoding="utf-8",
        )
        analyzer = QwikAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "devtools_enabled" for f in findings)
        assert any(f.kind == "csrf_disabled" for f in findings)
