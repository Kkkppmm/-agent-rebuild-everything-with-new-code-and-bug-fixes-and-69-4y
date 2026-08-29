"""Tests for v7.67.0 NuxtAnalyzer integration."""

from pathlib import Path

from devai import DevAI, NuxtAnalyzer
from devai.project_health import ProjectHealth

HARDENED_NUXT_CONFIG = """\
export default defineNuxtConfig({
  devtools: { enabled: false },
  ssr: true,
  telemetry: { enabled: false },
  sourcemap: { server: false, client: false },
  runtimeConfig: {
    public: {
      apiBase: 'https://api.example.com',
    },
  },
  vite: {
    server: {
      host: '127.0.0.1',
      fs: { allow: ['.'] },
      cors: false,
    },
  },
  security: {
    headers: {
      contentSecurityPolicy: true,
    },
  },
});
"""


class TestV767NuxtIntegration:
    def test_facade_nuxt(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(HARDENED_NUXT_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().nuxt(tmp_path)
        assert isinstance(analyzer, NuxtAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_nuxt_category(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(HARDENED_NUXT_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "nuxt" in names

    def test_public_exports(self):
        from devai import NuxtFinding, NuxtInfo, NuxtStats

        assert NuxtAnalyzer is not None
        assert NuxtFinding is not None
        assert NuxtInfo is not None
        assert NuxtStats is not None
