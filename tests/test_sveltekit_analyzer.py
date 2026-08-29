"""Tests for SvelteKitAnalyzer."""

from pathlib import Path

from devai.sveltekit_analyzer import SvelteKitAnalyzer, SvelteKitFinding


INSECURE_SVELTEKIT_CONFIG = """\
const config = {
  kit: {
    csrf: { checkOrigin: false, trustedOrigins: ['*'] },
    paths: { base: '../outside' },
    serviceWorker: { register: true },
  },
  vite: {
    server: {
      host: '0.0.0.0',
      cors: true,
      fs: { allow: ['..', '*'] },
    },
    build: { sourcemap: true },
  },
  api_key: 'api_key=hardcoded_secret_value_12345',
};
export default config;
"""

HARDENED_SVELTEKIT_CONFIG = """\
import adapter from '@sveltejs/adapter-auto';

const config = {
  kit: {
    adapter: adapter(),
    csrf: { checkOrigin: true, trustedOrigins: ['https://example.com'] },
  },
  vite: {
    server: { host: '127.0.0.1', fs: { allow: ['.'] }, cors: false },
    build: { sourcemap: false },
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
        assert "check_origin_disabled" in kinds
        assert "trusted_origins_wildcard" in kinds
        assert "host_exposed" in kinds
        assert "cors_open" in kinds
        assert "fs_allow_permissive" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "paths_relative" in kinds
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

    def test_finding_format(self):
        finding = SvelteKitFinding(
            kind="test",
            severity="high",
            message="test message",
            path="svelte.config.js",
            lineno=1,
        )
        assert "[high]" in finding.format()

    def test_generate_hardened_template(self):
        template = SvelteKitAnalyzer(".").generate_hardened_template()
        assert "checkOrigin: true" in template
