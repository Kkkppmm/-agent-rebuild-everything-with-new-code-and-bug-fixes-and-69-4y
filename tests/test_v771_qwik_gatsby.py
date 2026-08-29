"""Tests for v7.71.0 QwikAnalyzer and GatsbyAnalyzer integration."""

from pathlib import Path

from devai import DevAI, GatsbyAnalyzer, QwikAnalyzer
from devai.project_health import ProjectHealth

HARDENED_QWIK_VITE_CONFIG = """\
import { defineConfig } from 'vite';
import { qwikCity } from '@builder.io/qwik-city/vite';
import { qwikVite } from '@builder.io/qwik/optimizer';

export default defineConfig({
  plugins: [qwikCity(), qwikVite()],
  server: {
    host: '127.0.0.1',
    cors: false,
    fs: { allow: ['.'] },
  },
  preview: { host: '127.0.0.1', cors: false },
  build: { sourcemap: false },
  devTools: { enabled: false },
});
"""

HARDENED_GATSBY_CONFIG = """\
module.exports = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'https://example.com',
  },
  plugins: [],
  trailingSlash: 'never',
};
"""


class TestV771QwikGatsbyIntegration:
    def test_facade_qwik(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"@builder.io/qwik": "1.0.0"}}',
            encoding="utf-8",
        )
        (tmp_path / "vite.config.ts").write_text(HARDENED_QWIK_VITE_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().qwik(tmp_path)
        assert isinstance(analyzer, QwikAnalyzer)
        assert analyzer.stats.configs == 1

    def test_facade_gatsby(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().gatsby(tmp_path)
        assert isinstance(analyzer, GatsbyAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_qwik_category(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"@builder.io/qwik": "1.0.0"}}',
            encoding="utf-8",
        )
        (tmp_path / "vite.config.ts").write_text(HARDENED_QWIK_VITE_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "qwik" in names

    def test_project_health_includes_gatsby_category(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "gatsby" in names

    def test_public_exports(self):
        from devai import (
            GatsbyFinding,
            GatsbyInfo,
            GatsbyStats,
            QwikFinding,
            QwikInfo,
            QwikStats,
        )

        assert QwikAnalyzer is not None
        assert QwikFinding is not None
        assert QwikInfo is not None
        assert QwikStats is not None
        assert GatsbyAnalyzer is not None
        assert GatsbyFinding is not None
        assert GatsbyInfo is not None
        assert GatsbyStats is not None
