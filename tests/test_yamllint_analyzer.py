"""Tests for YamllintAnalyzer."""

from pathlib import Path

from devai.yamllint_analyzer import YamllintAnalyzer, YamllintFinding


INSECURE_YAMLLINT = """\
extends: relaxed

rules:
  truthy: disable
  key-duplicates: disable
  line-length:
    max: 500
  comments: disable
  empty-values: disable

ignore: |
  **/*
  .github/**

api_key: hardcoded_secret_value_12345
"""

INSECURE_YAMLLINT_NESTED = """\
extends: default

rules:
  truthy:
    enabled: false
  key-duplicates:
    enabled: false
  line-length:
    max: 300
"""

HARDENED_YAMLLINT = """\
extends: default

rules:
  truthy:
    check-keys: true
  key-duplicates: enable
  line-length:
    max: 120
    level: warning

ignore: |
  .git/
  .venv/
"""

INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.yamllint.rules.truthy]
enabled = false

[tool.yamllint.rules.key-duplicates]
enabled = false

api_key = api_key=hardcoded_secret_value_12345
"""


class TestYamllintAnalyzer:
    def test_detects_insecure_yamllint(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(INSECURE_YAMLLINT, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "truthy_disabled" in kinds
        assert "key_duplicates_disabled" in kinds
        assert "line_length_high" in kinds
        assert "broad_ignore" in kinds
        assert "relaxed_extends" in kinds
        assert "hardcoded_secret" in kinds
        assert "comments_disabled" in kinds
        assert "empty_values_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_nested_disabled_rules(self, tmp_path: Path):
        (tmp_path / ".yamllint.yaml").write_text(INSECURE_YAMLLINT_NESTED, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "truthy_disabled" in kinds
        assert "key_duplicates_disabled" in kinds
        assert "line_length_high" in kinds

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
        assert "hardcoded_secret" in kinds

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = YamllintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = YamllintFinding(
            kind="truthy_disabled",
            severity="high",
            message="truthy rule disabled",
            path=".yamllint",
            lineno=5,
            line="  truthy: disable",
        )
        assert "[high]" in finding.format()
        assert ".yamllint:5" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = YamllintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "extends: default" in template
        assert "key-duplicates: enable" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(INSECURE_YAMLLINT, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        assert "Yamllint configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Yamllint analysis:" in context
        assert "truthy_disabled" in context or "truthy" in context
