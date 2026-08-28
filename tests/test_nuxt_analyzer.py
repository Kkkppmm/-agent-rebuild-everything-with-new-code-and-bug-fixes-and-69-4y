"""Tests for NuxtAnalyzer."""

from pathlib import Path

from devai.nuxt_analyzer import NuxtAnalyzer, NuxtFinding


INSECURE_CONFIG = """\
export default defineNuxtConfig({
  ssr: false,

  runtimeConfig: {
    public: {
      apiKey: 'hardcoded_secret_value_12345',
      apiBase: 'http://insecure-api.example.com',
    },
  },

  nitro: {
    routeRules: {
      '/api/**': {
        headers: {
          'Access-Control-Allow-Origin': '*',
          contentSecurityPolicy: false,
        },
      },
    },
    devProxy: {
      '/internal': 'http://localhost:8080',
    },
  },

  vite: {
    server: {
      allowedHosts: true,
    },
  },

  modules: [
    'https://evil.example.com/nuxt-module.js',
  ],

  sourcemap: {
    client: true,
  },
})
"""

HARDENED_CONFIG = """\
export default defineNuxtConfig({
  ssr: true,

  runtimeConfig: {
    apiSecret: process.env.NUXT_API_SECRET,
    public: {
      apiBase: process.env.NUXT_PUBLIC_API_BASE || '/api',
    },
  },

  nitro: {
    routeRules: {
      '/**': {
        headers: {
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff',
        },
      },
    },
  },

  vite: {
    server: {
      allowedHosts: ['localhost'],
    },
  },

  sourcemap: {
    server: true,
    client: false,
  },
})
"""


class TestNuxtAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / "nuxt.config.ts").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = NuxtAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "ssr_disabled" in kinds
        assert "public_runtime_secret" in kinds
        assert "cors_wildcard" in kinds
        assert "security_headers_disabled" in kinds
        assert "dev_proxy" in kinds
        assert "allowed_hosts_all" in kinds
        assert "remote_module" in kinds
        assert "client_sourcemap" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "nuxt.config.js").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = NuxtAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].ssr_enabled is True
        assert analyzer.infos[0].file_kind == "javascript"

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = NuxtAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = NuxtFinding(
            kind="ssr_disabled",
            severity="medium",
            message="SSR disabled",
            path="nuxt.config.ts",
            lineno=2,
            line="ssr: false,",
        )
        assert "[medium] nuxt.config.ts:2" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = NuxtAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "ssr: true" in template
        assert "runtimeConfig" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "nuxt.config.mjs").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = NuxtAnalyzer(str(tmp_path))
        assert "1 file(s)" in analyzer.summary()
        context = analyzer.to_context()
        assert "nuxt analysis:" in context
        assert "health score:" in context
