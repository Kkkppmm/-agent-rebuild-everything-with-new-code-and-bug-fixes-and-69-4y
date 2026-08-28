"""Tests for MarkdownlintAnalyzer."""

from pathlib import Path

from devai.markdownlint_analyzer import MarkdownlintAnalyzer, MarkdownlintFinding


INSECURE_MARKDOWNLINT = """\
{
  "default": false,
  "MD033": false,
  "MD045": false,
  "MD046": false,
  "MD013": { "line_length": 5000 },
  "allowed_elements": ["*"],
  "ignores": ["**/*"],
  "api_key": "hardcoded_secret_value_12345"
}
"""

HARDENED_MARKDOWNLINT = """\
{
  "default": true,
  "MD013": { "line_length": 120 },
  "MD033": { "allowed_elements": ["details", "summary"] },
  "MD045": true,
  "MD046": { "style": "fenced" }
}
"""


class TestMarkdownlintAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / ".markdownlint.json").write_text(
            INSECURE_MARKDOWNLINT,
            encoding="utf-8",
        )
        analyzer = MarkdownlintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "default_disabled" in kinds
        assert "md033_disabled" in kinds
        assert "md045_disabled" in kinds
        assert "hardcoded_secret" in kinds
        assert "allowed_elements_all" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".markdownlint.json").write_text(
            HARDENED_MARKDOWNLINT,
            encoding="utf-8",
        )
        analyzer = MarkdownlintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].default_enabled is True

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = MarkdownlintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = MarkdownlintFinding(
            kind="md033_disabled",
            severity="high",
            message="test message",
            path=".markdownlint.json",
            lineno=3,
            line='"MD033": false',
        )
        assert ".markdownlint.json:3" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = MarkdownlintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert '"default": true' in template
        assert "MD033" in template

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".markdownlint.json").write_text(
            '{"default": false, "MD033": false}\n',
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        markdownlint = next(c for c in report.categories if c.name == "markdownlint")
        assert markdownlint.score < 100.0
        assert markdownlint.details.get("findings", 0) > 0
