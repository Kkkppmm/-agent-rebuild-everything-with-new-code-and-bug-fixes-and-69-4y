"""Tests for QwikAnalyzer."""

from pathlib import Path

from devai.qwik_analyzer import QwikAnalyzer, QwikFinding


INSECURE_QWIK_VITE_CONFIG = """\
import { defineConfig } from 'vite';
import { qwikCity } from '@builder.io/qwik-city/vite';

export default defineConfig({
  plugins: [qwikCity()],
  origin: 'http://example.com',
  ssr: false,
  preview: { host: '0.0.0.0', port: 4173 },
  server: {
    host: '0.0.0.0',
    cors: true,
    fs: { allow: ['..', '*'] },
  },
  build: { sourcemap: true },
  api_key: 'api_key=hardcoded_secret_value_12345',
});
"""

HARDENED_QWIK_VITE_CONFIG = """\
import { defineConfig } from 'vite';
import { qwikCity } from '@builder.io/qwik-city/vite';
import { qwikVite } from '@builder.io/qwik/optimizer';

export default defineConfig({
  plugins: [qwikCity(), qwikVite()],
  preview: { host: '127.0.0.1', port: 4173 },
  server: { host: '127.0.0.1', fs: { allow: ['.'] }, cors: false },
  build: { sourcemap: false },
});
"""


def _setup_qwik_project(tmp_path: Path, config: str) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@builder.io/qwik": "1.0.0", "@builder.io/qwik-city": "1.0.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "vite.config.ts").write_text(config, encoding="utf-8")


class TestQwikAnalyzer:
    def test_detects_insecure_qwik_config(self, tmp_path: Path):
        _setup_qwik_project(tmp_path, INSECURE_QWIK_VITE_CONFIG)
        analyzer = QwikAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "origin_http" in kinds
        assert "host_exposed" in kinds
        assert "preview_host_exposed" in kinds
        assert "cors_open" in kinds
        assert "fs_allow_permissive" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "ssr_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_qwik_config_scores_well(self, tmp_path: Path):
        _setup_qwik_project(tmp_path, HARDENED_QWIK_VITE_CONFIG)
        analyzer = QwikAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = QwikAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = QwikFinding(
            kind="test",
            severity="high",
            message="test message",
            path="vite.config.ts",
            lineno=1,
        )
        assert "[high]" in finding.format()

    def test_generate_hardened_template(self):
        template = QwikAnalyzer(".").generate_hardened_template()
        assert "host: '127.0.0.1'" in template
        assert "sourcemap: false" in template
