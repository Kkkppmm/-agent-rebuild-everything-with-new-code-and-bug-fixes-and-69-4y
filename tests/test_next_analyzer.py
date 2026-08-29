"""Tests for NextAnalyzer."""

from pathlib import Path

from devai.next_analyzer import NextAnalyzer, NextFinding


INSECURE_NEXT_CONFIG = """\
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  poweredByHeader: true,
  productionBrowserSourceMaps: true,
  typescript: { ignoreBuildErrors: true },
  eslint: { ignoreDuringBuilds: true },
  images: {
    unoptimized: true,
    dangerouslyAllowSVG: true,
    contentSecurityPolicy: false,
    remotePatterns: [
      { protocol: 'http', hostname: '*', pathname: '/**' },
    ],
  },
  env: {
    API_KEY: 'api_key=hardcoded_secret_value_12345',
  },
  async rewrites() {
    return [{ source: '/api', destination: 'http://10.0.0.1:8080' }];
  },
  headers: async () => [
    { source: '/(.*)', headers: [{ key: 'Access-Control-Allow-Origin', value: '*' }] },
  ],
  experimental: {
    allowedDevOrigins: ['*'],
    serverActions: { allowedOrigins: ['*'] },
  },
  trailingSlash: false,
  output: 'export',
  api_key: 'api_key=hardcoded_secret_value_12345',
};

export default nextConfig;
"""

HARDENED_NEXT_CONFIG = """\
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  typescript: { ignoreBuildErrors: false },
  eslint: { ignoreDuringBuilds: false },
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'example.com', pathname: '/images/**' },
    ],
    dangerouslyAllowSVG: false,
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
  },
};

export default nextConfig;
"""


class TestNextAnalyzer:
    def test_detects_insecure_next_config(self, tmp_path: Path):
        (tmp_path / "next.config.ts").write_text(INSECURE_NEXT_CONFIG, encoding="utf-8")
        analyzer = NextAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "production_sourcemaps" in kinds
        assert "ignore_typescript_errors" in kinds
        assert "ignore_eslint" in kinds
        assert "dangerously_allow_svg" in kinds
        assert "csp_disabled" in kinds
        assert "cors_wildcard" in kinds
        assert "rewrite_internal" in kinds
        assert "env_secret" in kinds
        assert "remote_pattern_wildcard" in kinds
        assert "remote_pattern_http" in kinds
        assert "allowed_dev_origins_wildcard" in kinds
        assert "server_actions_origins_wildcard" in kinds
        assert "powered_by_header" in kinds
        assert "unoptimized_images" in kinds
        assert "trailing_slash_false" in kinds
        assert "static_export" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_next_config_scores_well(self, tmp_path: Path):
        (tmp_path / "next.config.ts").write_text(HARDENED_NEXT_CONFIG, encoding="utf-8")
        analyzer = NextAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = NextAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no configuration" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = NextFinding(
            kind="test",
            severity="high",
            message="test message",
            path="next.config.ts",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "next.config.ts").write_text(HARDENED_NEXT_CONFIG, encoding="utf-8")
        analyzer = NextAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Next.js configuration analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = NextAnalyzer(".").generate_hardened_template()
        assert "poweredByHeader: false" in template
        assert "productionBrowserSourceMaps: false" in template

    def test_detects_js_config(self, tmp_path: Path):
        (tmp_path / "next.config.js").write_text(
            "module.exports = { poweredByHeader: true };\n",
            encoding="utf-8",
        )
        analyzer = NextAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "powered_by_header" for f in findings)
