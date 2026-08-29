"""Tests for YamllintAnalyzer."""

from pathlib import Path

from devai.yamllint_analyzer import YamllintAnalyzer, YamllintFinding


INSECURE_CONFIG = """\
extends: relaxed

rules:
  truthy: disable
  key-duplicates: disable
  octal-values: disable
  quoted-strings: disable
  line-length:
    max: 500
  comments:
    min-spaces-from-content: 0

ignore: |
  .github/
  k8s/
  deploy/
  helm/

api_key: hardcoded_secret_value_12345
"""

HARDENED_CONFIG = """\
extends: default

rules:
  line-length:
    max: 120
    allow-non-breakable-inline-mappings: true
  truthy:
    allowed-values: ['true', 'false']
    check-keys: true
  key-duplicates: enable
  octal-values: enable
  document-start: disable
  new-line-at-end-of-file: enable
  comments:
    min-spaces-from-content: 2

ignore: |
  .git/
  node_modules/
"""

OBJECT_DISABLE_CONFIG = """\
extends: default

rules:
  truthy:
    disable: true
  key-duplicates:
    disable: true
"""


class TestYamllintAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "extends_relaxed" in kinds
        assert "truthy_disabled" in kinds
        assert "key_duplicates_disabled" in kinds
        assert "octal_values_disabled" in kinds
        assert "quoted_strings_disabled" in kinds
        assert "ignore_sensitive_path" in kinds
        assert "line_length_high" in kinds
        assert "comments_spaces_low" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".yamllint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].extends == "default"
        assert analyzer.infos[0].line_length_max == 120

    def test_object_disable_syntax(self, tmp_path: Path):
        (tmp_path / ".yamllint.yml").write_text(OBJECT_DISABLE_CONFIG, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "truthy_disabled" in kinds
        assert "key_duplicates_disabled" in kinds

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
            lineno=4,
            line="  truthy: disable",
        )
        assert "[high] .yamllint:4" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = YamllintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "extends: default" in template
        assert "key-duplicates: enable" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = YamllintAnalyzer(str(tmp_path))
        assert "1 file(s)" in analyzer.summary()
        context = analyzer.to_context()
        assert "yamllint analysis:" in context
        assert "health score:" in context
