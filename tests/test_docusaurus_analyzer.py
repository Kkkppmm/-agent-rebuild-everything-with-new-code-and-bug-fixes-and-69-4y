"""Tests for DocusaurusAnalyzer."""

from pathlib import Path

from devai.docusaurus_analyzer import DocusaurusAnalyzer, DocusaurusFinding


INSECURE_CONFIG = """\
/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Insecure Docs',
  url: 'http://evil.example.com',
  baseUrl: '/',
  onBrokenLinks: 'ignore',
  onBrokenMarkdownLinks: 'ignore',
  api_key: 'sk-live-secret-token-12345',
  scripts: [
    'https://evil.example.com/tracker.js',
  ],
  headTags: [
    { tagName: 'script', attributes: { src: 'https://evil.example.com/xss.js' } },
  ],
  clientModules: ['https://evil.example.com/module.js'],
  plugins: ['https://evil.example.com/plugin.js'],
  customFields: { secret_token: 'hardcoded-value' },
  themeConfig: {
    algolia: {
      appId: 'APPID',
      apiKey: 'a1b2c3d4e5f6789012345678abcdef01',
    },
    googleAnalytics: { trackingID: 'UA-123456-1' },
  },
};

module.exports = config;
"""

HARDENED_CONFIG = """\
/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Secure Docs',
  url: 'https://example.com',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',
  organizationName: 'org',
  projectName: 'repo',
  presets: [
    [
      'classic',
      {
        docs: { sidebarPath: require.resolve('./sidebars.js') },
        theme: { customCss: require.resolve('./src/css/custom.css') },
      },
    ],
  ],
  themeConfig: {
    navbar: { title: 'Secure Docs' },
  },
  scripts: [],
  headTags: [],
  customFields: {},
};

module.exports = config;
"""


class TestDocusaurusAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        website = tmp_path / "website"
        website.mkdir()
        (website / "docusaurus.config.js").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "broken_links_ignore" in kinds
        assert "broken_markdown_ignore" in kinds
        assert "external_scripts" in kinds
        assert "remote_script" in kinds
        assert "remote_client_module" in kinds
        assert "remote_plugin" in kinds
        assert "custom_fields_secret" in kinds
        assert "algolia_admin_key" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        website = tmp_path / "website"
        website.mkdir()
        (website / "docusaurus.config.js").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_root_config_also_scanned(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.ts").write_text(
            "export default { title: 'Docs', onBrokenLinks: 'ignore', themeConfig: {} };",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "broken_links_ignore" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_ignores_non_docusaurus_config(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(
            "module.exports = { title: 'Not Docusaurus' };",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = DocusaurusAnalyzer(".").generate_hardened_template()
        assert "onBrokenLinks: 'throw'" in template
        assert "scripts: []" in template

    def test_finding_format(self):
        finding = DocusaurusFinding(
            kind="broken_links_ignore",
            severity="medium",
            message="test message",
            path="website/docusaurus.config.js",
            lineno=5,
        )
        assert "medium" in finding.format()
        assert "website/docusaurus.config.js:5" in finding.format()

    def test_to_context(self, tmp_path: Path):
        website = tmp_path / "website"
        website.mkdir()
        (website / "docusaurus.config.js").write_text(
            "const config = { onBrokenLinks: 'ignore', themeConfig: {} }; module.exports = config;",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Docusaurus analysis:" in context
        assert "broken_links" in context.lower() or "ignore" in context

    def test_summary(self, tmp_path: Path):
        website = tmp_path / "website"
        website.mkdir()
        (website / "docusaurus.config.js").write_text(
            "const config = { onBrokenLinks: 'ignore', themeConfig: {} }; module.exports = config;",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Docusaurus configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        website = tmp_path / "website"
        website.mkdir()
        (website / "docusaurus.config.js").write_text(
            "const config = { onBrokenLinks: 'ignore', scripts: ['https://evil.com/x.js'], themeConfig: {} };"
            " module.exports = config;",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        docusaurus = next(c for c in report.categories if c.name == "docusaurus")
        assert docusaurus.score < 100.0
        assert docusaurus.details.get("findings", 0) > 0
