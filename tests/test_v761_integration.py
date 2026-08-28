"""Tests for v7.61.0 HadolintAnalyzer and NuxtAnalyzer integration."""

from pathlib import Path

from devai import DevAI, HadolintAnalyzer, NuxtAnalyzer
from devai.project_health import ProjectHealth

HARDENED_HADOLINT = """\
failure-threshold: error
ignored: []
trustedRegistries:
  - docker.io
"""

HARDENED_NUXT = """\
export default defineNuxtConfig({
  ssr: true,
  devtools: { enabled: false },
  telemetry: false,
})
"""


class TestV761Integration:
    def test_facade_hadolint(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(HARDENED_HADOLINT, encoding="utf-8")
        analyzer = DevAI.mock().hadolint(tmp_path)
        assert isinstance(analyzer, HadolintAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_facade_nuxt(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(HARDENED_NUXT, encoding="utf-8")
        analyzer = DevAI.mock().nuxt(tmp_path)
        assert isinstance(analyzer, NuxtAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_hadolint_category(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(HARDENED_HADOLINT, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "hadolint" in names

    def test_project_health_includes_nuxt_category(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(HARDENED_NUXT, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "nuxt" in names

    def test_public_exports(self):
        from devai import (
            HadolintFinding,
            HadolintInfo,
            HadolintStats,
            NuxtFinding,
            NuxtInfo,
            NuxtStats,
        )

        assert HadolintAnalyzer is not None
        assert HadolintFinding is not None
        assert HadolintInfo is not None
        assert HadolintStats is not None
        assert NuxtAnalyzer is not None
        assert NuxtFinding is not None
        assert NuxtInfo is not None
        assert NuxtStats is not None
