"""Tests for v7.71.0 QwikAnalyzer integration."""

from pathlib import Path

from devai import DevAI, QwikAnalyzer
from devai.project_health import ProjectHealth

HARDENED_QWIK_CONFIG = """\
import { defineConfig } from '@builder.io/qwik-city/vite';

export default defineConfig(() => ({
  server: {
    host: 'localhost',
    strictPort: true,
    origin: 'https://localhost:5173',
  },
  build: {
    sourcemap: false,
  },
}));
"""


class TestV771QwikIntegration:
    def test_facade_qwik(self, tmp_path: Path):
        (tmp_path / "qwik.config.ts").write_text(HARDENED_QWIK_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().qwik(tmp_path)
        assert isinstance(analyzer, QwikAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_qwik_category(self, tmp_path: Path):
        (tmp_path / "qwik.config.ts").write_text(HARDENED_QWIK_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "qwik" in names

    def test_public_exports(self):
        from devai import QwikFinding, QwikInfo, QwikStats

        assert QwikAnalyzer is not None
        assert QwikFinding is not None
        assert QwikInfo is not None
        assert QwikStats is not None
