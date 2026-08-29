"""Tests for v7.69.0 RemixAnalyzer integration."""

from pathlib import Path

from devai import DevAI, RemixAnalyzer
from devai.project_health import ProjectHealth

HARDENED_REMIX_CONFIG = """\
/** @type {import('@remix-run/dev').AppConfig} */
export default {
  appDirectory: 'app',
  assetsBuildDirectory: 'public/build',
  publicPath: '/build/',
  serverBuildPath: 'build/index.js',
  serverModuleFormat: 'esm',
  serverMinify: true,
  ignoredRouteFiles: ['**/.*'],
  watchPaths: ['.'],
  future: {},
};
"""


class TestV769RemixIntegration:
    def test_facade_remix(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().remix(tmp_path)
        assert isinstance(analyzer, RemixAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_remix_category(self, tmp_path: Path):
        (tmp_path / "remix.config.js").write_text(HARDENED_REMIX_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "remix" in names

    def test_public_exports(self):
        from devai import RemixFinding, RemixInfo, RemixStats

        assert RemixAnalyzer is not None
        assert RemixFinding is not None
        assert RemixInfo is not None
        assert RemixStats is not None
