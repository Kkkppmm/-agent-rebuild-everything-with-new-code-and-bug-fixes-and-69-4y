"""Tests for NuxtAnalyzer."""

from pathlib import Path

from devai.nuxt_analyzer import NuxtAnalyzer, NuxtFinding


INSECURE_NUXT_CONFIG = """\
export default defineNuxtConfig({
  devtools: { enabled: true },
  ssr: false,
  telemetry: { enabled: true },
  sourcemap: { server: true, client: true },
  runtimeConfig: {
    apiSecret: 'super_secret_api_key_12345',
    authSecret: 'auth_secret_hardcoded',
    public: {
      apiBase: 'http://example.com/api',
    },
  },
  nitro: {
    routeRules: {
      '/api/**': { proxy: 'http://10.0.0.1:8080/**' },
    },
    devProxy: {
      '/backend': { target: 'http://192.168.1.1/admin', rejectUnauthorized: false },
    },
  },
  vite: {
    server: {
      host: '0.0.0.0',
      cors: true,
      fs: { allow: ['..', '*'] },
    },
  },
  security: {
    headers: {
      contentSecurityPolicy: false,
    },
  },
  image: {
    remotePatterns: [
      { protocol: 'http', hostname: '*', pathname: '/**' },
    ],
  },
  api_key: 'api_key=hardcoded_secret_value_12345',
});
"""

HARDENED_NUXT_CONFIG = """\
export default defineNuxtConfig({
  devtools: { enabled: false },
  ssr: true,
  telemetry: { enabled: false },
  sourcemap: { server: false, client: false },
  runtimeConfig: {
    public: {
      apiBase: 'https://api.example.com',
    },
  },
  nitro: {
    routeRules: {
      '/api/**': { cors: false },
    },
  },
  vite: {
    server: {
      host: '127.0.0.1',
      fs: { allow: ['.'] },
      cors: false,
    },
  },
  security: {
    headers: {
      contentSecurityPolicy: true,
      crossOriginResourcePolicy: 'same-origin',
    },
  },
});
"""


class TestNuxtAnalyzer:
    def test_detects_insecure_nuxt_config(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(INSECURE_NUXT_CONFIG, encoding="utf-8")
        analyzer = NuxtAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "runtime_config_secret" in kinds
        assert "public_runtime_http" in kinds
        assert "devtools_enabled" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "csp_disabled" in kinds
        assert "cors_open" in kinds
        assert "host_exposed" in kinds
        assert "fs_allow_permissive" in kinds
        assert "proxy_internal" in kinds
        assert "remote_pattern_wildcard" in kinds
        assert "remote_pattern_http" in kinds
        assert "route_rule_proxy" in kinds
        assert "ssr_disabled" in kinds
        assert "telemetry_enabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_nuxt_config_scores_well(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(HARDENED_NUXT_CONFIG, encoding="utf-8")
        analyzer = NuxtAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = NuxtAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = NuxtFinding(
            kind="test",
            severity="high",
            message="test message",
            path="nuxt.config.ts",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(HARDENED_NUXT_CONFIG, encoding="utf-8")
        analyzer = NuxtAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Nuxt configuration analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = NuxtAnalyzer(".").generate_hardened_template()
        assert "devtools: { enabled: false }" in template
        assert "contentSecurityPolicy: true" in template

    def test_detects_js_config(self, tmp_path: Path):
        (tmp_path / "nuxt.config.js").write_text(
            "export default { devtools: true };\n",
            encoding="utf-8",
        )
        analyzer = NuxtAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "devtools_enabled" for f in findings)
