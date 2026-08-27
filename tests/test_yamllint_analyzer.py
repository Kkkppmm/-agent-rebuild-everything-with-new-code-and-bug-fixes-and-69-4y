"""Tests for YamllintAnalyzer."""

from pathlib import Path

from devai.yamllint_analyzer import YamllintAnalyzer, YamllintFinding


INSECURE_YAMLLINT = """\
extends: default

rules:
  truthy: false
  key-duplicates:
    enabled: false
  line-length:
    max: 300
  document-start: false
  empty-values:
    forbid-in-block-mappings: false
  comments:
    ignore: "*"
ignore: "*"
api_key: hardcoded_secret_value_12345
"""

HARDENED_YAMLLINT = """\
extends: default

rules:
  truthy:
    enabled: true
  key-duplicates:
    enabled: true
  line-length:
    max: 120
  document-start:
    present: false
  comments:
    ignore: |
      ^# SPDX-License-Identifier
"""

INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.yamllint]
extends = "default"
truthy = false
key-duplicates = false
line-length = 300
"""


class TestYamllintAnalyzer:
    def test_detects_insecure_yamllint(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(INSECURE_YAMLLINT, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "truthy_disabled" in kinds
        assert "key_duplicates_disabled" in kinds
        assert "line_length_high" in kinds
        assert "document_start_disabled" in kinds
        assert "empty_values_disabled" in kinds
        assert "broad_ignore" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_yamllint_scores_well(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(HARDENED_YAMLLINT, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].extends == "default"

    def test_pyproject_toml_section(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "truthy_disabled" in kinds
        assert "key_duplicates_disabled" in kinds
        assert all(f.lineno >= 5 for f in findings)

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
            line="truthy: false",
        )
        assert ".yamllint:5" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = YamllintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "extends: default" in template
        assert "truthy:" in template
        assert "key-duplicates:" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text("rules:\n  truthy: false\n", encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Yamllint analysis:" in context
        assert "truthy rule disabled" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".yamllint").write_text("rules:\n  truthy: false\n", encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        yamllint = next(c for c in report.categories if c.name == "yamllint")
        assert yamllint.score < 100.0
        assert yamllint.details.get("findings", 0) > 0
