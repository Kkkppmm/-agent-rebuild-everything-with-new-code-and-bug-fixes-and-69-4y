"""Tests for v7.66.0 AstroAnalyzer integration."""

from pathlib import Path

from devai import AstroAnalyzer, DevAI
from devai.project_health import ProjectHealth

HARDENED_ASTRO_CONFIG = """\
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://example.com',
  compressHTML: true,
  devToolbar: { enabled: false },
  security: {
    checkOrigin: true,
    allowedDomains: ['example.com'],
  },
  image: {
    remotePatterns: [
      { protocol: 'https', hostname: 'example.com', pathname: '/images/**' },
    ],
  },
});
"""


class TestV766AstroIntegration:
    def test_facade_astro(self, tmp_path: Path):
        (tmp_path / "astro.config.mjs").write_text(HARDENED_ASTRO_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().astro(tmp_path)
        assert isinstance(analyzer, AstroAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_astro_category(self, tmp_path: Path):
        (tmp_path / "astro.config.mjs").write_text(HARDENED_ASTRO_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "astro" in names

    def test_public_exports(self):
        from devai import AstroFinding, AstroInfo, AstroStats

        assert AstroAnalyzer is not None
        assert AstroFinding is not None
        assert AstroInfo is not None
        assert AstroStats is not None
