"""Tests for SvelteKitAnalyzer."""

from pathlib import Path

from devai.sveltekit_analyzer import SvelteKitAnalyzer, SvelteKitFinding


INSECURE_SVELTEKIT_CONFIG = """\
import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({ credentials: { accessKeyId: 'AKIA123', secretAccessKey: 'secret' } }),
    csrf: { checkOrigin: false, trustedOrigins: ['*'] },
    csp: { mode: 'off' },
    version: { poll: 5000 },
    embedded: true,
    vite: {
      server: {
        host: true,
        cors: true,
        fs: { allow: ['..', '*'] },
      },
    },
    env: { API_KEY: 'api_key=hardcoded_secret_value_12345' },
    api_key: 'api_key=hardcoded_secret_value_12345',
  },
};

export default config;
"""

HARDENED_SVELTEKIT_CONFIG = """\
import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    csrf: { checkOrigin: true, trustedOrigins: ['https://example.com'] },
    csp: { mode: 'auto' },
    embedded: false,
  },
};

export default config;
"""


class TestSvelteKitAnalyzer:
    def test_detects_insecure_sveltekit_config(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(INSECURE_SVELTEKIT_CONFIG, encoding="utf-8")
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "csrf_disabled" in kinds
        assert "csrf_trusted_wildcard" in kinds
        assert "csp_disabled" in kinds
        assert "host_exposed" in kinds
        assert "cors_open" in kinds
        assert "adapter_secret" in kinds
        assert "env_secret" in kinds
        assert "embedded_enabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_sveltekit_config_scores_well(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(HARDENED_SVELTEKIT_CONFIG, encoding="utf-8")
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = SvelteKitFinding(
            kind="test",
            severity="high",
            message="test message",
            path="svelte.config.js",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(HARDENED_SVELTEKIT_CONFIG, encoding="utf-8")
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "SvelteKit configuration analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = SvelteKitAnalyzer(".").generate_hardened_template()
        assert "checkOrigin: true" in template
        assert "mode: 'auto'" in template
