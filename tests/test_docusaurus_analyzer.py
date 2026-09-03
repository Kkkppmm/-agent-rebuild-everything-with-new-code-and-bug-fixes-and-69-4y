"""Tests for DocusaurusAnalyzer."""

from pathlib import Path

from devai.docusaurus_analyzer import DocusaurusAnalyzer, DocusaurusFinding


INSECURE_CONFIG = """\
import {themes as prismThemes} from 'prism-react-renderer';

const apiKey = 'sk-live-secret-token-12345';
const algoliaApiKey = 'a1b2c3d4e5f6789012345678901234ab';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Insecure Docs',
  url: 'http://insecure.example.com',
  baseUrl: '/',
  onBrokenLinks: 'ignore',
  onBrokenMarkdownLinks: 'warn',
  trailingSlash: false,

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.js',
          path: '../outside-docs',
          editUrl: 'http://github.com/user:pass@evil.example.com/repo/edit/',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      },
    ],
  ],

  themeConfig: {
    algolia: {
      appId: 'MYAPPID',
      apiKey: 'a1b2c3d4e5f6789012345678901234ab',
      indexName: 'docs',
    },
    scripts: [
      'https://cdn.example.com/analytics.js',
    ],
  },

  markdown: {
    mdx1Compat: {
      comments: true,
      admonitions: true,
      headingIds: true,
    },
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  customFields: {
    apiKey: 'super-secret-key',
    buildEnv: process.env.INTERNAL_API_TOKEN,
  },

  plugins: [
    function configureWebpack() {
      return {
        configureWebpack() {
          return {};
        },
      };
    },
  ],
};

eval('console.log("bad")');
const {execSync} = require('child_process');
execSync('echo bad');

export default config;
"""

HARDENED_CONFIG = """\
import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Secure Docs',
  url: 'https://docs.example.com',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',
  trailingSlash: true,

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/my-org/my-project/tree/main/website/',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      },
    ],
  ],

  themeConfig: {
    navbar: {
      title: 'Secure Docs',
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  },
};

export default config;
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
        assert "broken_links_ignored" in kinds
        assert "algolia_admin_key" in kinds
        assert "custom_fields_secret" in kinds
        assert "parent_path" in kinds
        assert "eval_exec" in kinds
        assert "shell_execution" in kinds
        assert "env_exposed_to_client" in kinds
        assert "trailing_slash_false" in kinds
        assert "edit_url_http" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        website = tmp_path / "website"
        website.mkdir()
        (website / "docusaurus.config.js").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_typescript_config_scanned(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.ts").write_text(
            "export default { title: 'x', url: 'https://x.com', onBrokenLinks: 'ignore' };\n",
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

    def test_ignores_non_docusaurus_js(self, tmp_path: Path):
        (tmp_path / "docusaurus.config.js").write_text(
            "module.exports = { port: 3000, debug: true };\n",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        analyzer = DocusaurusAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "onBrokenLinks: 'throw'" in template
        assert "https://" in template

    def test_summary_and_context(self, tmp_path: Path):
        website = tmp_path / "website"
        website.mkdir()
        (website / "docusaurus.config.js").write_text(
            "export default { title: 'x', url: 'http://bad.com', onBrokenLinks: 'throw' };\n",
            encoding="utf-8",
        )
        analyzer = DocusaurusAnalyzer(str(tmp_path))
        assert "Docusaurus configs:" in analyzer.summary()
        assert "Docusaurus analysis:" in analyzer.to_context()

    def test_finding_format(self):
        finding = DocusaurusFinding(
            kind="test",
            severity="high",
            message="test message",
            path="website/docusaurus.config.js",
            lineno=10,
        )
        assert "high" in finding.format()
        assert "test message" in finding.format()
