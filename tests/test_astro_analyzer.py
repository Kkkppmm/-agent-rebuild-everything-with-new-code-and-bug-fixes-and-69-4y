"""Tests for AstroAnalyzer."""

from pathlib import Path

from devai.astro_analyzer import AstroAnalyzer, AstroFinding


INSECURE_ASTRO_CONFIG = """\
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'http://example.com',
  compressHTML: false,
  devToolbar: { enabled: true },
  security: {
    checkOrigin: false,
    allowedDomains: ['*'],
  },
  image: {
    domains: ['*'],
    remotePatterns: [
      { protocol: 'http', hostname: '*', pathname: '/**' },
    ],
  },
  server: {
    host: true,
    port: 4321,
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
  prefetch: { prefetchAll: true },
  build: {
    inlineStylesheets: 'always',
  },
  env: {
    API_KEY: 'api_key=hardcoded_secret_value_12345',
  },
  adapter: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  },
  redirects: {
    '/old': { status: 302, destination: 'http://192.168.1.1/admin' },
  },
  api_key: 'api_key=hardcoded_secret_value_12345',
});
"""

HARDENED_ASTRO_CONFIG = """\
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://example.com',
  compressHTML: true,
  devToolbar: { enabled: false },
  security: {
    checkOrigin: true,
    allowedDomains: ['example.com'],
  },
  image: {
    remotePatterns: [
      { protocol: 'https', hostname: 'example.com', pathname: '/images/**' },
    ],
  },
  server: {
    host: '127.0.0.1',
    port: 4321,
  },
  vite: {
    server: {
      fs: { allow: ['.'] },
      cors: false,
    },
    build: {
      sourcemap: false,
    },
  },
});
"""


class TestAstroAnalyzer:
    def test_detects_insecure_astro_config(self, tmp_path: Path):
        (tmp_path / "astro.config.mjs").write_text(INSECURE_ASTRO_CONFIG, encoding="utf-8")
        analyzer = AstroAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "site_http" in kinds
        assert "check_origin_disabled" in kinds
        assert "allowed_domains_wildcard" in kinds
        assert "dev_toolbar_enabled" in kinds
        assert "image_domain_wildcard" in kinds
        assert "remote_pattern_wildcard" in kinds
        assert "remote_pattern_http" in kinds
        assert "host_exposed" in kinds
        assert "fs_allow_permissive" in kinds
        assert "cors_open" in kinds
        assert "proxy_internal" in kinds
        assert "sourcemaps_enabled" in kinds
        assert "env_secret" in kinds
        assert "adapter_secret" in kinds
        assert "redirect_internal" in kinds
        assert "prefetch_all" in kinds
        assert "compress_html_disabled" in kinds
        assert "inline_stylesheets_always" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_astro_config_scores_well(self, tmp_path: Path):
        (tmp_path / "astro.config.mjs").write_text(HARDENED_ASTRO_CONFIG, encoding="utf-8")
        analyzer = AstroAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = AstroAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = AstroFinding(
            kind="test",
            severity="high",
            message="test message",
            path="astro.config.mjs",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "astro.config.mjs").write_text(HARDENED_ASTRO_CONFIG, encoding="utf-8")
        analyzer = AstroAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Astro configuration analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = AstroAnalyzer(".").generate_hardened_template()
        assert "checkOrigin: true" in template
        assert "devToolbar: { enabled: false }" in template

    def test_detects_ts_config(self, tmp_path: Path):
        (tmp_path / "astro.config.ts").write_text(
            "export default { devToolbar: true };\n",
            encoding="utf-8",
        )
        analyzer = AstroAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "dev_toolbar_enabled" for f in findings)
