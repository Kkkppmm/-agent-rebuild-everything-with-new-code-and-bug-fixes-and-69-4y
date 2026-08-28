"""Tests for v7.68.0 SvelteKitAnalyzer integration."""

from pathlib import Path

from devai import DevAI, SvelteKitAnalyzer
from devai.project_health import ProjectHealth

HARDENED_SVELTE_CONFIG = """\
import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    csrf: { checkOrigin: true },
    csp: { mode: 'auto' },
    env: { publicPrefix: 'PUBLIC_' },
    prerender: { origin: 'https://example.com' },
    serviceWorker: { register: false },
    experimental: { inspector: false },
    version: { pollInterval: 0 },
  },
  vite: {
    server: {
      host: '127.0.0.1',
      fs: { allow: ['.'] },
      cors: false,
    },
  },
};
"""

INSECURE_SVELTE_CONFIG = """\
export default {
  kit: {
    csrf: { checkOrigin: false },
    csp: false,
    prerender: { origin: 'http://api.example.com' },
    serviceWorker: { register: true },
    experimental: { inspector: true },
    version: { pollInterval: 5000 },
  },
  vite: {
    server: { host: true, cors: true },
  },
};
"""


class TestV768SvelteKitIntegration:
    def test_facade_sveltekit(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(HARDENED_SVELTE_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().sveltekit(tmp_path)
        assert isinstance(analyzer, SvelteKitAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_sveltekit_category(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(HARDENED_SVELTE_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "sveltekit" in names

    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(INSECURE_SVELTE_CONFIG, encoding="utf-8")
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "check_origin_disabled" in kinds
        assert analyzer.stats.high_severity >= 1

    def test_generate_hardened_template(self):
        template = SvelteKitAnalyzer(".").generate_hardened_template()
        assert "checkOrigin: true" in template
        assert "SvelteKitAnalyzer" in template

    def test_public_exports(self):
        from devai import SvelteKitFinding, SvelteKitInfo, SvelteKitStats

        assert SvelteKitAnalyzer is not None
        assert SvelteKitFinding is not None
        assert SvelteKitInfo is not None
        assert SvelteKitStats is not None
