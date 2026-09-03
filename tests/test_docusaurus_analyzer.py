"""Tests for DocusaurusAnalyzer."""

from pathlib import Path

from devai.docusaurus_analyzer import DocusaurusAnalyzer, DocusaurusFinding


INSECURE_DOCUSAURUS = """\
import {themes as prismThemes} from 'prism-react-renderer';

const config = {
  title: 'Demo Docs',
  url: 'http://insecure.example.com',
  baseUrl: '/docs/',
  organizationName: 'org',
  projectName: 'repo',

  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'ignore',

  presets: [
    ['classic', {
      docs: { editUrl: 'https://user:secretpass@github.com/org/repo' },
    }],
  ],

  themeConfig: {
    algolia: {
      appId: 'APPID',
      apiKey: 'super-secret-search-key',
      indexName: 'docs',
    },
  },

  customFields: {
    apiKey: 'hardcoded-key',
    password: 'admin123',
  },

  scripts: ['https://cdn.example.com/analytics.js'],
  stylesheets: ['https://cdn.example.com/theme.css'],

  markdown: {
    mdx1Compat: { comments: true },
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },
};

export default config;
"""

HARDENED_DOCUSAURUS = """\
import {themes as prismThemes} from 'prism-react-renderer';

const config = {
  title: 'Demo Docs',
  url: 'https://example.com',
  baseUrl: '/docs/',
  organizationName: 'org',
  projectName: 'repo',

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',
  trailingSlash: true,

  presets: [
    ['classic', {
      docs: { editUrl: 'https://github.com/org/repo/tree/main/' },
      theme: { customCss: './src/css/custom.css' },
    }],
  ],

  themeConfig: {
    navbar: {
      title: 'Demo Docs',
      items: [{type: 'docSidebar', sidebarId: 'tutorialSidebar', label: 'Docs'}],
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  },

  scripts: [],
  stylesheets: [],
};

export default config;
"""


class TestDocusaurusAnalyzer:
    def test_detects_insecure_docusaurus_config(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.ts").write_text(INSECURE_DOCUSAURUS, encoding="utf-8")
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "broken_links_relaxed" in kinds
        assert "credential_in_url" in kinds
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_docusaurus_scores_well(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(HARDENED_DOCUSAURUS, encoding="utf-8")
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_docusaurus_js_also_scanned(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(
            "export default { onBrokenLinks: 'ignore' };\n",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "broken_links_relaxed" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = DocusaurusAnalyzer(".").generate_hardened_template()
        assert "onBrokenLinks: 'throw'" in template
        assert "scripts: []" in template

    def test_finding_format(self):
        finding = DocusaurusFinding(
            kind="test",
            severity="high",
            message="test message",
            path="docusaurus.config.ts",
            lineno=1,
            line="test line",
        )
        assert "[high]" in finding.format()
        assert "docusaurus.config.ts:1" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.ts").write_text(
            "export default { url: 'http://evil.example.com' };\n",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        assert "Docusaurus configs:" in analyzer.summary()
        assert "health score:" in analyzer.to_context()

    def test_detects_eval(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(
            "const x = eval('1+1'); export default {};\n",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "eval_usage" for f in findings)

    def test_detects_host_exposed(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(
            "export default { host: '0.0.0.0' };\n",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "host_exposed" for f in findings)
