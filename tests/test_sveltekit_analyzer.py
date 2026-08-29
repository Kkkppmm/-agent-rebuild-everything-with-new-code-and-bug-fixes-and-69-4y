"""Tests for SvelteKitAnalyzer."""

from pathlib import Path

from devai.sveltekit_analyzer import SvelteKitAnalyzer, SvelteKitFinding


INSECURE_SVELTEKIT_CONFIG = """\
import adapter from '@sveltejs/adapter-node';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    adapter: adapter({
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    }),
    csrf: {
      checkOrigin: false,
      trustedOrigins: ['*'],
    },
    csp: false,
    env: {
      public: {
        API_KEY: 'hardcoded_public_api_key_12345',
      },
      private: {
        SECRET: 'hardcoded_private_secret',
      },
    },
    embedded: true,
    serviceWorker: { register: true },
    prerender: { handleMissingId: 'ignore' },
    version: { pollInterval: 60000 },
  },
  vite: {
    server: {
      host: '0.0.0.0',
      cors: true,
      fs: { allow: ['..', '*'] },
      proxy: {
        '/api': { target: 'http://10.0.0.1:8080', rejectUnauthorized: false },
      },
    },
    build: {
      sourcemap: true,
    },
  },
  api_key: 'api_key=hardcoded_secret_value_12345',
};

export default config;
"""

HARDENED_SVELTEKIT_CONFIG = """\
import adapter from '@sveltejs/adapter-auto';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    csrf: {
      checkOrigin: true,
    },
    csp: {
      mode: 'auto',
      directives: {
        'default-src': ['self'],
      },
    },
    env: {
      publicPrefix: 'PUBLIC_',
    },
    prerender: {
      handleMissingId: 'warn',
    },
  },
  vite: {
    server: {
      host: '127.0.0.1',
      fs: { allow: ['.'] },
      cors: false,
    },
    build: {
      sourcemap: false,
    },
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
        assert "adapter_secret" in kinds
        assert "csrf_origin_disabled" in kinds
        assert "csrf_trusted_wildcard" in kinds
        assert "csp_disabled" in kinds
        assert "cors_open" in kinds
        assert "host_exposed" in kinds
        assert "fs_allow_permissive" in kinds
        assert "proxy_internal" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "embedded_mode" in kinds
        assert "service_worker_register" in kinds
        assert "prerender_missing_ignored" in kinds
        assert "version_poll_enabled" in kinds
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
        assert "csp:" in template

    def test_detects_ts_config(self, tmp_path: Path):
        (tmp_path / "svelte.config.ts").write_text(
            "export default { kit: { csrf: { checkOrigin: false } } };\n",
            encoding="utf-8",
        )
        analyzer = SvelteKitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "csrf_origin_disabled" for f in findings)
