"""Tests for DocusaurusAnalyzer."""

from pathlib import Path

from devai.docusaurus_analyzer import DocusaurusAnalyzer, DocusaurusFinding


INSECURE_DOCUSAURUS = """\
const config = {
  title: 'Demo Docs',
  url: 'http://insecure.example.com',
  api_key: 'sk-live-hardcoded-secret',

  onBrokenLinks: 'ignore',
  debug: true,

  customFields: {
    apiSecret: 'super-secret-token',
  },

  scripts: [
    { src: 'https://cdn.example.com/analytics.js', async: true },
  ],

  stylesheets: [
    'https://cdn.example.com/theme.css',
  ],

  clientModules: [
    'https://cdn.example.com/widget.js',
  ],

  markdown: {
    mdx1Compat: {
      comments: true,
    },
    mermaid: true,
    rehypePlugins: [
      ['rehype-raw', { allowDangerousHtml: true }],
    ],
  },

  webpack: {
    devtool: 'eval-source-map',
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

  presets: [
    [
      'classic',
      {
        docs: { sidebarPath: './sidebars.js' },
        theme: { customCss: './src/css/custom.css' },
      },
    ],
  ],

  themeConfig: {
    navbar: { title: 'Demo Docs' },
  },

  scripts: [],
  stylesheets: [],
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
        assert "hardcoded_secret" in kinds
        assert "custom_fields_secret" in kinds
        assert "remote_script" in kinds
        assert "ignore_broken_links" in kinds
        assert "debug_mode" in kinds
        assert "dangerous_remark_plugin" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_docusaurus_scores_well(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(HARDENED_DOCUSAURUS, encoding="utf-8")
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_config_files_discovery(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.ts").write_text(HARDENED_DOCUSAURUS, encoding="utf-8")
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(INSECURE_DOCUSAURUS, encoding="utf-8")
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        assert "Docusaurus configs:" in analyzer.summary()
        assert "Docusaurus analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = DocusaurusAnalyzer(".").generate_hardened_template()
        assert "onBrokenLinks: 'throw'" in template
        assert "scripts: []" in template

    def test_finding_format(self):
        finding = DocusaurusFinding(
            kind="test",
            severity="high",
            message="test message",
            path="docusaurus.config.js",
            lineno=1,
        )
        assert "[high]" in finding.format()

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()
