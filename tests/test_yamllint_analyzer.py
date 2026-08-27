"""Tests for YamllintAnalyzer."""

from pathlib import Path

from devai.yamllint_analyzer import YamllintAnalyzer, YamllintFinding


INSECURE_YAMLLINT = """\
extends: relaxed

ignore: |
  .github/
  k8s/
  deploy/

rules:
  line-length:
    max: 300
    level: warning
  truthy:
    check-keys: false
    allowed-values: ['true', 'false']
  key-duplicates: disable
  document-start: disable
  empty-values: disable
  comments: disable
  api_key: api_key=hardcoded_secret_value_12345
"""

HARDENED_YAMLLINT = """\
extends: default

ignore: |
  .git/
  .venv/

rules:
  line-length:
    max: 120
    level: warning
  truthy:
    check-keys: true
    allowed-values: ['true', 'false', 'on', 'off']
  key-duplicates: enable
  document-start: disable
  empty-values:
    forbid-in-block-mappings: true
"""


class TestYamllintAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(INSECURE_YAMLLINT, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "extends_relaxed" in kinds
        assert "truthy_check_keys_disabled" in kinds
        assert "key_duplicates_disabled" in kinds
        assert "line_length_high" in kinds
        assert "document_start_disabled" in kinds
        assert "empty_values_disabled" in kinds
        assert "comments_disabled" in kinds
        assert "broad_ignore" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(HARDENED_YAMLLINT, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].extends == "default"

    def test_supports_yaml_extension(self, tmp_path: Path):
        (tmp_path / ".yamllint.yaml").write_text(
            "rules:\n  truthy: disable\n",
            encoding="utf-8",
        )
        analyzer = YamllintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "truthy_disabled" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = YamllintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = YamllintFinding(
            kind="truthy_disabled",
            severity="high",
            message="test message",
            path=".yamllint",
            lineno=5,
            line="truthy: disable",
        )
        assert ".yamllint:5" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = YamllintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "extends: default" in template
        assert "check-keys: true" in template
        assert "key-duplicates: enable" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(
            "rules:\n  truthy: disable\n",
            encoding="utf-8",
        )
        analyzer = YamllintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Yamllint analysis:" in context
        assert "truthy" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".yamllint").write_text(
            "rules:\n  key-duplicates: disable\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        yamllint = next(c for c in report.categories if c.name == "yamllint")
        assert yamllint.score < 100.0
        assert yamllint.details.get("findings", 0) > 0
