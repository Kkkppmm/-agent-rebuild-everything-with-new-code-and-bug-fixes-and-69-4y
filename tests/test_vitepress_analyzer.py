"""Tests for VitePressAnalyzer."""

from pathlib import Path

from devai.vitepress_analyzer import VitePressAnalyzer, VitePressFinding


INSECURE_CONFIG = """\
import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Demo Docs',
  apiKey: 'sk-live-secret-token-12345',
  host: '0.0.0.0',
  head: [
    ['script', { src: 'https://cdn.example.com/jquery.min.js' }],
  ],
  markdown: {
    html: true,
    unsafe: true,
  },
  themeConfig: {
    algolia: {
      appId: 'ABC123',
      apiKey: 'hardcoded-search-key-xyz',
      indexName: 'docs',
    },
  },
  sitemap: {
    hostname: 'http://insecure.example.com',
  },
})
"""

HARDENED_CONFIG = """\
import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Demo Docs',
  description: 'Documentation',
  head: [],
  markdown: {
    html: false,
  },
  themeConfig: {
    nav: [{ text: 'Guide', link: '/guide/' }],
    search: { provider: 'local' },
  },
  sitemap: {
    hostname: 'https://example.com',
  },
})
"""


class TestVitePressAnalyzer:
    def test_detects_insecure_vitepress_config(self, tmp_path: Path):
        vp = tmp_path / ".vitepress"
        vp.mkdir()
        (vp / "config.ts").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "markdown_unsafe" in kinds
        assert "host_exposed" in kinds
        assert "algolia_hardcoded_key" in kinds
        assert "insecure_http" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        vp = tmp_path / ".vitepress"
        vp.mkdir()
        (vp / "config.ts").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_docs_vitepress_also_scanned(self, tmp_path: Path):
        vp = tmp_path / "docs" / ".vitepress"
        vp.mkdir(parents=True)
        (vp / "config.js").write_text(
            "export default { title: 'x', markdown: { html: true } }\n",
            encoding="utf-8",
        )
        analyzer = VitePressAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "markdown_unsafe" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = VitePressAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_ignores_non_vitepress_config(self, tmp_path: Path):
        (tmp_path / "config.ts").write_text("export const DEBUG = true\n", encoding="utf-8")
        analyzer = VitePressAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = VitePressAnalyzer(".").generate_hardened_template()
        assert "html: false" in template
        assert "https://example.com" in template

    def test_finding_format(self):
        finding = VitePressFinding(
            kind="markdown_unsafe",
            severity="high",
            message="test message",
            path=".vitepress/config.ts",
            lineno=2,
        )
        assert "high" in finding.format()
        assert ".vitepress/config.ts:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        vp = tmp_path / ".vitepress"
        vp.mkdir()
        (vp / "config.ts").write_text(
            "export default { title: 'x', markdown: { html: true } }\n",
            encoding="utf-8",
        )
        analyzer = VitePressAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "VitePress analysis:" in context
        assert "markdown.html/unsafe" in context

    def test_summary(self, tmp_path: Path):
        vp = tmp_path / ".vitepress"
        vp.mkdir()
        (vp / "config.ts").write_text(
            "export default { title: 'x', markdown: { html: true } }\n",
            encoding="utf-8",
        )
        analyzer = VitePressAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "VitePress configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        vp = tmp_path / ".vitepress"
        vp.mkdir()
        (vp / "config.ts").write_text(
            "export default { title: 'x', markdown: { html: true }, apiKey: 'secret123' }\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        vitepress = next(c for c in report.categories if c.name == "vitepress")
        assert vitepress.score < 100.0
        assert vitepress.details.get("findings", 0) > 0
