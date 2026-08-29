"""Tests for SvelteKitAnalyzer."""

from pathlib import Path

from devai.sveltekit_analyzer import SvelteKitAnalyzer, SvelteKitFinding


INSECURE_SVELTE_CONFIG = """\
import adapter from '@sveltejs/adapter-node';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    adapter: adapter({
      env: { sessionSecret: 'hardcoded_session_secret_abc123' },
    }),
    csrf: { checkOrigin: false, trustedOrigins: ['*'] },
    csp: false,
    paths: { base: 'http://example.com' },
    prerender: { origin: 'http://example.com' },
    env: { API_KEY: 'hardcoded_api_key_value_12345' },
  },
};

export default config;
"""

HARDENED_SVELTE_CONFIG = """\
import adapter from '@sveltejs/adapter-node';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    adapter: adapter(),
    csrf: { checkOrigin: true },
    csp: { mode: 'auto' },
    paths: { relative: true },
  },
};

export default config;
"""

INSECURE_VITE_CONFIG = """\
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    host: '0.0.0.0',
    cors: true,
    fs: { allow: ['..', '*'] },
    proxy: { '/api': { target: 'http://10.0.0.1:8080' } },
  },
  build: { sourcemap: true },
  api_key: 'api_key=hardcoded_secret_value_12345',
});
"""


class TestSvelteKitAnalyzer:
    def test_detects_insecure_svelte_config(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(INSECURE_SVELTE_CONFIG, encoding="utf-8")
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "adapter_secret" in kinds
        assert "check_origin_disabled" in kinds
        assert "trusted_origin_wildcard" in kinds
        assert "paths_base_http" in kinds
        assert "prerender_origin_http" in kinds
        assert "csp_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_svelte_config_scores_well(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(HARDENED_SVELTE_CONFIG, encoding="utf-8")
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = SvelteKitFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="svelte.config.js",
            lineno=10,
            line="secret: 'x'",
        )
        assert "high" in finding.format()
        assert "svelte.config.js:10" in finding.format()

    def test_to_context_includes_score(self, tmp_path: Path):
        (tmp_path / "svelte.config.js").write_text(HARDENED_SVELTE_CONFIG, encoding="utf-8")
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "health score" in context
        assert "svelte.config.js" in context

    def test_generate_hardened_template(self):
        analyzer = SvelteKitAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "checkOrigin: true" in template
        assert "adapter-node" in template

    def test_detects_insecure_vite_config(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(INSECURE_VITE_CONFIG, encoding="utf-8")
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "host_exposed" in kinds
        assert "proxy_internal" in kinds
        assert "fs_allow_permissive" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "hardcoded_secret" in kinds

    def test_ignores_non_sveltekit_vite_config(self, tmp_path: Path):
        (tmp_path / "vite.config.ts").write_text(
            "export default { plugins: [], server: { host: '0.0.0.0' } };",
            encoding="utf-8",
        )
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
