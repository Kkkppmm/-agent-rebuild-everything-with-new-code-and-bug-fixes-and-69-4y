"""Tests for HadolintAnalyzer."""

from pathlib import Path

from devai.hadolint_analyzer import HadolintAnalyzer, HadolintFinding


INSECURE_CONFIG = """\
failure-threshold: info

ignored:
  - DL3002
  - DL3004
  - DL3006
  - DL3007
  - DL3013
  - DL3045
  - DL4006
  - SC2086

trustedRegistries:
  - "*"
  - "*.example.com"
  - docker.io

api_key: hardcoded_secret_value_12345
"""

HARDENED_CONFIG = """\
failure-threshold: warning

ignored: []

trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io

override:
  error:
    - DL3002
    - DL3004
    - DL3006
    - DL3007
"""

INSECURE_JSON = """\
{
  "failure-threshold": "style",
  "ignored": ["DL3002", "DL3007", "SC2016"],
  "trustedRegistries": ["*"]
}
"""


class TestHadolintAnalyzer:
    def test_detects_insecure_yaml_config(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "permissive_failure_threshold" in kinds
        assert "ignored_root_user_rule" in kinds
        assert "ignored_tag_rule" in kinds
        assert "ignored_version_pin_rule" in kinds
        assert "ignored_healthcheck_rule" in kinds
        assert "ignored_shell_rule" in kinds
        assert "trusted_registry_wildcard" in kinds
        assert "trusted_registry_broad" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".hadolint.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_json_config(self, tmp_path: Path):
        (tmp_path / ".hadolint.json").write_text(INSECURE_JSON, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "permissive_failure_threshold" in kinds
        assert "ignored_root_user_rule" in kinds
        assert "ignored_tag_rule" in kinds
        assert "ignored_shell_rule" in kinds
        assert "trusted_registry_wildcard" in kinds

    def test_finding_format(self):
        finding = HadolintFinding(
            kind="ignored_root_user_rule",
            severity="high",
            message="ignored DL3002",
            path=".hadolint.yaml",
            lineno=4,
            line="  - DL3002",
        )
        assert "[high] .hadolint.yaml:4" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = HadolintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "failure-threshold: warning" in template
        assert "DL3002" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "hadolint analysis:" in context
        assert "health score: 100.0/100" in context

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = HadolintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "hadolint configs: none found"
