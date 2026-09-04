"""Tests for VitePressAnalyzer."""

from pathlib import Path

from devai.vitepress_analyzer import VitePressAnalyzer, VitePressFinding


INSECURE_VITEPRESS = """\
import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Demo Docs',
  api_key: 'sk-live-hardcoded-secret',

  server: {
    host: '0.0.0.0',
  },

  head: [
    ['script', { src: 'https://cdn.example.com/analytics.js' }],
  ],

  define: {
    __API_SECRET__: 'super-secret-token',
  },

  markdown: {
    html: true,
  },

  transformHtml: (code) => code,

  ignoreDeadLinks: 'ignore',
})
"""

HARDENED_VITEPRESS = """\
import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Demo Docs',

  server: {
    host: '127.0.0.1',
  },

  themeConfig: {
    nav: [{ text: 'Home', link: '/' }],
  },

  head: [],

  markdown: {
    html: false,
  },
})
"""


class TestVitePressAnalyzer:
    def test_detects_insecure_vitepress_config(self, tmp_path: Path):
        vitepress = tmp_path / ".vitepress"
        vitepress.mkdir()
        (vitepress / "config.ts").write_text(INSECURE_VITEPRESS, encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "host_all_interfaces" in kinds
        assert "hardcoded_secret" in kinds
        assert "define_secret" in kinds
        assert "markdown_unsafe" in kinds
        assert "transform_html" in kinds
        assert "ignore_dead_links" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_vitepress_scores_well(self, tmp_path: Path):
        vitepress = tmp_path / ".vitepress"
        vitepress.mkdir()
        (vitepress / "config.ts").write_text(HARDENED_VITEPRESS, encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_config_files_discovery(self, tmp_path: Path):
        vitepress = tmp_path / ".vitepress"
        vitepress.mkdir()
        (vitepress / "config.js").write_text(HARDENED_VITEPRESS, encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_summary_and_context(self, tmp_path: Path):
        vitepress = tmp_path / ".vitepress"
        vitepress.mkdir()
        (vitepress / "config.ts").write_text(INSECURE_VITEPRESS, encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        assert "VitePress configs:" in analyzer.summary()
        assert "VitePress analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = VitePressAnalyzer(".").generate_hardened_template()
        assert "127.0.0.1" in template
        assert "html: false" in template

    def test_finding_format(self):
        finding = VitePressFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".vitepress/config.ts",
            lineno=1,
        )
        assert "[high]" in finding.format()

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = VitePressAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()
