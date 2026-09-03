"""Tests for VitePressAnalyzer."""

from pathlib import Path

from devai.vitepress_analyzer import VitePressAnalyzer, VitePressFinding


INSECURE_VITEPRESS = """\
import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Demo Docs',
  head: [['script', { src: 'https://cdn.example.com/analytics.js' }]],
  markdown: {
    html: true,
  },
  vite: {
    server: {
      host: '0.0.0.0',
      fs: {
        allow: ['../outside', '/tmp/untrusted'],
      },
    },
  },
  themeConfig: {
    editLink: {
      pattern: 'https://user:secretpass@github.com/org/repo/edit/main/:path',
    },
    algolia: {
      appId: 'APPID',
      apiKey: 'a1b2c3d4e5f6789012345678901234ab',
      indexName: 'docs',
    },
  },
  onDeadLink: 'ignore',
})
"""

HARDENED_VITEPRESS = """\
import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Demo Docs',
  vite: {
    server: {
      host: '127.0.0.1',
      fs: {
        allow: ['.'],
      },
    },
  },
  themeConfig: {
    search: {
      provider: 'local',
    },
  },
  markdown: {
    html: false,
  },
})
"""


class TestVitePressAnalyzer:
    def test_detects_insecure_vitepress_config(self, tmp_path: Path):
        config_dir = tmp_path / ".vitepress"
        config_dir.mkdir()
        (config_dir / "config.ts").write_text(INSECURE_VITEPRESS, encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "server_host_all" in kinds
        assert "fs_allow_parent" in kinds
        assert "credential_in_url" in kinds
        assert "markdown_unsafe" in kinds
        assert "broken_links_ignored" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_vitepress_scores_well(self, tmp_path: Path):
        config_dir = tmp_path / ".vitepress"
        config_dir.mkdir()
        (config_dir / "config.ts").write_text(HARDENED_VITEPRESS, encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_config_js_also_scanned(self, tmp_path: Path):
        config_dir = tmp_path / ".vitepress"
        config_dir.mkdir()
        (config_dir / "config.js").write_text("export default { vite: { server: { host: '0.0.0.0' } } }", encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "server_host_all" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = VitePressAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = VitePressAnalyzer(".").generate_hardened_template()
        assert "127.0.0.1" in template
        assert "html: false" in template

    def test_finding_format(self):
        finding = VitePressFinding(
            kind="server_host_all",
            severity="medium",
            message="test message",
            path=".vitepress/config.ts",
            lineno=2,
        )
        assert "medium" in finding.format()
        assert ".vitepress/config.ts:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        config_dir = tmp_path / ".vitepress"
        config_dir.mkdir()
        (config_dir / "config.ts").write_text("export default { vite: { server: { host: '0.0.0.0' } } }", encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "VitePress analysis:" in context
        assert "server" in context

    def test_summary(self, tmp_path: Path):
        config_dir = tmp_path / ".vitepress"
        config_dir.mkdir()
        (config_dir / "config.ts").write_text("export default { vite: { server: { host: '0.0.0.0' } } }", encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "VitePress configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        config_dir = tmp_path / ".vitepress"
        config_dir.mkdir()
        (config_dir / "config.ts").write_text(
            "export default { vite: { server: { host: '0.0.0.0' } }, markdown: { html: true } }",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        vitepress = next(c for c in report.categories if c.name == "vitepress")
        assert vitepress.score < 100.0
        assert vitepress.details.get("findings", 0) > 0
