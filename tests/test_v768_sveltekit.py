"""Tests for v7.68.0 SvelteKitAnalyzer integration."""

from pathlib import Path

from devai import DevAI, SvelteKitAnalyzer
from devai.project_health import ProjectHealth

HARDENED_SVELTEKIT_CONFIG = """\
import adapter from '@sveltejs/adapter-auto';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    adapter: adapter(),
    csrf: { checkOrigin: true },
    csp: { mode: 'auto', directives: { 'default-src': ['self'] } },
    env: { publicPrefix: 'PUBLIC_' },
  },
  vite: {
    server: { host: '127.0.0.1', fs: { allow: ['.'] }, cors: false },
    build: { sourcemap: false },
  },
};

export default config;
"""


class TestV768SvelteKitIntegration:
    def test_facade_sveltekit(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(HARDENED_SVELTEKIT_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().sveltekit(tmp_path)
        assert isinstance(analyzer, SvelteKitAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_sveltekit_category(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(HARDENED_SVELTEKIT_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "sveltekit" in names

    def test_public_exports(self):
        from devai import SvelteKitFinding, SvelteKitInfo, SvelteKitStats

        assert SvelteKitAnalyzer is not None
        assert SvelteKitFinding is not None
        assert SvelteKitInfo is not None
        assert SvelteKitStats is not None
