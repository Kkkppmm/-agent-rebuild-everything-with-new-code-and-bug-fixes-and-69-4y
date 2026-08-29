"""Tests for v7.68.0 SvelteKit, Gatsby, and Qwik analyzer integration."""

from pathlib import Path

from devai import DevAI, GatsbyAnalyzer, QwikAnalyzer, SvelteKitAnalyzer
from devai.project_health import ProjectHealth

HARDENED_SVELTEKIT_CONFIG = """\
import adapter from '@sveltejs/adapter-node';

const config = {
  kit: {
    adapter: adapter(),
    csrf: { checkOrigin: true, trustedOrigins: ['https://example.com'] },
    csp: { mode: 'auto' },
  },
};

export default config;
"""

HARDENED_GATSBY_CONFIG = """\
module.exports = {
  siteMetadata: { title: 'My Site', siteUrl: 'https://example.com' },
  plugins: ['gatsby-plugin-react-helmet'],
};
"""

HARDENED_QWIK_CONFIG = """\
import { defineConfig } from 'vite';

export default defineConfig({
  server: { host: '127.0.0.1', cors: false },
  build: { sourcemap: false },
});
"""


class TestV768FrameworkIntegration:
    def test_facade_sveltekit(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(HARDENED_SVELTEKIT_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().sveltekit(tmp_path)
        assert isinstance(analyzer, SvelteKitAnalyzer)
        assert analyzer.stats.configs == 1

    def test_facade_gatsby(self, tmp_path: Path):
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().gatsby(tmp_path)
        assert isinstance(analyzer, GatsbyAnalyzer)
        assert analyzer.stats.configs == 1

    def test_facade_qwik(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(HARDENED_QWIK_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().qwik(tmp_path)
        assert isinstance(analyzer, QwikAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_framework_categories(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(HARDENED_SVELTEKIT_CONFIG, encoding="utf-8")
        (tmp_path / "gatsby-config.js").write_text(HARDENED_GATSBY_CONFIG, encoding="utf-8")
        (tmp_path / "vite.config.ts").write_text(HARDENED_QWIK_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "sveltekit" in names
        assert "gatsby" in names
        assert "qwik" in names

    def test_public_exports(self):
        from devai import (
            GatsbyFinding,
            GatsbyInfo,
            GatsbyStats,
            QwikFinding,
            QwikInfo,
            QwikStats,
            SvelteKitFinding,
            SvelteKitInfo,
            SvelteKitStats,
        )

        assert SvelteKitAnalyzer is not None
        assert GatsbyAnalyzer is not None
        assert QwikAnalyzer is not None
        assert SvelteKitFinding is not None
        assert GatsbyFinding is not None
        assert QwikFinding is not None
        assert SvelteKitInfo is not None
        assert GatsbyInfo is not None
        assert QwikInfo is not None
        assert SvelteKitStats is not None
        assert GatsbyStats is not None
        assert QwikStats is not None
