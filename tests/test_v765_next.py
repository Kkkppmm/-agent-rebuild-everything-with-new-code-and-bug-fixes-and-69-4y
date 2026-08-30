"""Tests for v7.65.0 NextAnalyzer integration."""

from pathlib import Path

from devai import DevAI, NextAnalyzer
from devai.project_health import ProjectHealth

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


class TestV765NextIntegration:
    def test_facade_next(self, tmp_path: Path):
        (tmp_path / "next.config.ts").write_text(HARDENED_NEXT_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().next(tmp_path)
        assert isinstance(analyzer, NextAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_next_category(self, tmp_path: Path):
        (tmp_path / "next.config.ts").write_text(HARDENED_NEXT_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "next" in names

    def test_public_exports(self):
        from devai import NextFinding, NextInfo, NextStats

        assert NextAnalyzer is not None
        assert NextFinding is not None
        assert NextInfo is not None
        assert NextStats is not None
