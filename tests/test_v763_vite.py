"""Tests for v7.63.0 ViteAnalyzer integration."""

from pathlib import Path

from devai import DevAI, ViteAnalyzer
from devai.project_health import ProjectHealth

HARDENED_VITE_CONFIG = """\
import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    host: 'localhost',
    strictPort: true,
    cors: { origin: 'http://localhost:5173' },
    fs: { allow: ['.'] },
  },
  build: {
    sourcemap: false,
    minify: 'esbuild',
  },
  envPrefix: 'VITE_',
});
"""


class TestV763ViteIntegration:
    def test_facade_vite(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(HARDENED_VITE_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().vite(tmp_path)
        assert isinstance(analyzer, ViteAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_vite_category(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(HARDENED_VITE_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "vite" in names

    def test_public_exports(self):
        from devai import ViteFinding, ViteInfo, ViteStats

        assert ViteAnalyzer is not None
        assert ViteFinding is not None
        assert ViteInfo is not None
        assert ViteStats is not None
