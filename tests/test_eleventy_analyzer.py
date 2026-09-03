"""Tests for EleventyAnalyzer."""

from pathlib import Path

from devai.eleventy_analyzer import EleventyAnalyzer, EleventyFinding


INSECURE_ELEVENTY = """\
module.exports = function (eleventyConfig) {
  eleventyConfig.setServerOptions({
    showAllHosts: true,
    host: "0.0.0.0",
  });

  eleventyConfig.setNunjucksEnvironmentOptions({
    autoescape: false,
  });

  eleventyConfig.setLiquidOptions({
    dynamicPartials: true,
  });

  eleventyConfig.addGlobalData("apiKey", "sk-hardcoded-secret");

  eleventyConfig.addPassthroughCopy("https://cdn.example.com/assets");

  eleventyConfig.amendLibrary("md", (mdLib) => {
    mdLib.set({ html: true });
  });

  const plugin = require("https://cdn.example.com/plugin.js");
  eleventyConfig.addPlugin(plugin);

  eval("console.log('bad')");

  return {
    dir: {
      input: "src",
      output: "dist",
    },
    url: "http://insecure.example.com",
    watch: true,
  };
};
"""

HARDENED_ELEVENTY = """\
module.exports = function (eleventyConfig) {
  eleventyConfig.setServerOptions({
    showAllHosts: false,
    host: "127.0.0.1",
  });

  eleventyConfig.setNunjucksEnvironmentOptions({
    autoescape: true,
  });

  eleventyConfig.setLiquidOptions({
    dynamicPartials: false,
  });

  eleventyConfig.amendLibrary("md", (mdLib) => {
    mdLib.set({ html: false, linkify: true });
  });

  return {
    dir: {
      input: "src",
      output: "dist",
      includes: "_includes",
      data: "_data",
    },
    pathPrefix: "/",
  };
};
"""


class TestEleventyAnalyzer:
    def test_detects_insecure_eleventy_config(self, tmp_path: Path):
        (tmp_path / ".eleventy.js").write_text(INSECURE_ELEVENTY, encoding="utf-8")
        analyzer = EleventyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "show_all_hosts" in kinds
        assert "bind_all_interfaces" in kinds
        assert "autoescape_disabled" in kinds
        assert "markdown_html_enabled" in kinds
        assert "hardcoded_secret" in kinds
        assert "remote_passthrough" in kinds
        assert "remote_plugin" in kinds
        assert "eval_exec" in kinds
        assert "insecure_http" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_eleventy_scores_well(self, tmp_path: Path):
        (tmp_path / "eleventy.config.js").write_text(HARDENED_ELEVENTY, encoding="utf-8")
        analyzer = EleventyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_config_files_discovery(self, tmp_path: Path):
        (tmp_path / "eleventy.config.mjs").write_text(HARDENED_ELEVENTY, encoding="utf-8")
        analyzer = EleventyAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / ".eleventy.js").write_text(INSECURE_ELEVENTY, encoding="utf-8")
        analyzer = EleventyAnalyzer(str(tmp_path))
        assert "Eleventy configs:" in analyzer.summary()
        assert "Eleventy analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = EleventyAnalyzer(".").generate_hardened_template()
        assert "showAllHosts: false" in template
        assert "autoescape: true" in template
        assert "127.0.0.1" in template

    def test_finding_format(self):
        finding = EleventyFinding(
            kind="autoescape_disabled",
            severity="high",
            message="test",
            path=".eleventy.js",
            lineno=1,
        )
        assert ".eleventy.js:1" in finding.format()
