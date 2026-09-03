"""Tests for DocusaurusAnalyzer."""

from pathlib import Path

from devai.docusaurus_analyzer import DocusaurusAnalyzer, DocusaurusFinding


INSECURE_DOCUSAURUS = """\
const config = {
  title: 'Demo Docs',
  url: 'http://insecure.example.com',
  baseUrl: '/',
  onBrokenLinks: 'ignore',
  onBrokenMarkdownLinks: 'ignore',
  trailingSlash: false,
  noIndex: false,
  scripts: [
    { src: 'https://cdn.example.com/analytics.js', async: true },
  ],
  customFields: {
    apiKey: 'super-secret-key-value',
  },
  themeConfig: {
    algolia: {
      appId: 'APPID',
      apiKey: 'a1b2c3d4e5f6789012345678901234ab',
      indexName: 'docs',
    },
  },
};

export default config;
"""

HARDENED_DOCUSAURUS = """\
const config = {
  title: 'Demo Docs',
  url: 'https://example.com',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  trailingSlash: true,
  presets: [
    [
      'classic',
      {
        docs: {
          editUrl: 'https://github.com/org/repo/edit/main/',
        },
      },
    ],
  ],
};

export default config;
"""


class TestDocusaurusAnalyzer:
    def test_detects_insecure_docusaurus_config(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(INSECURE_DOCUSAURUS, encoding="utf-8")
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "broken_links_ignored" in kinds
        assert "remote_script" in kinds
        assert "custom_fields_secret" in kinds
        assert "trailing_slash_false" in kinds
        assert "no_index_false" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_docusaurus_scores_well(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(HARDENED_DOCUSAURUS, encoding="utf-8")
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_config_ts_also_scanned(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.ts").write_text(
            "export default { onBrokenLinks: 'ignore' }",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "broken_links_ignored" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = DocusaurusAnalyzer(".").generate_hardened_template()
        assert "onBrokenLinks: 'throw'" in template
        assert "trailingSlash: true" in template

    def test_finding_format(self):
        finding = DocusaurusFinding(
            kind="broken_links_ignored",
            severity="medium",
            message="test message",
            path="docusaurus.config.js",
            lineno=2,
        )
        assert "medium" in finding.format()
        assert "docusaurus.config.js:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(
            "export default { onBrokenLinks: 'ignore' }",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Docusaurus analysis:" in context
        assert "broken" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(
            "export default { onBrokenLinks: 'ignore' }",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Docusaurus configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "docusaurus.config.js").write_text(
            "export default { onBrokenLinks: 'ignore', url: 'http://insecure.example.com' }",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        docusaurus = next(c for c in report.categories if c.name == "docusaurus")
        assert docusaurus.score < 100.0
        assert docusaurus.details.get("findings", 0) > 0
