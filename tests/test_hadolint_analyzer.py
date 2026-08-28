"""Tests for HadolintAnalyzer."""

from pathlib import Path

from devai.hadolint_analyzer import HadolintAnalyzer, HadolintFinding


INSECURE_CONFIG = """\
failure-threshold: style
strict-labels: false

ignored:
  - DL3006
  - DL3007
  - DL3008
  - DL3018
  - DL3002
  - DL3025
  - DL4006
  - SC2086

trustedRegistries:
  - http://insecure-registry.example.com
  - "*"

api_key: hardcoded_secret_value_12345
"""

HARDENED_CONFIG = """\
failure-threshold: warning
strict-labels: true

allowedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io

trustedRegistries:
  - docker.io
  - gcr.io

ignored: []
"""

WILDCARD_IGNORE_CONFIG = """\
ignored:
  - DL*
"""


class TestHadolintAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "failure_threshold_low" in kinds
        assert "strict_labels_disabled" in kinds
        assert "tagging_rule_ignored" in kinds
        assert "pinning_rule_ignored" in kinds
        assert "user_rule_ignored" in kinds
        assert "copy_rule_ignored" in kinds
        assert "shell_rule_ignored" in kinds
        assert "shellcheck_rule_ignored" in kinds
        assert "trusted_registry_http" in kinds
        assert "trusted_registry_wildcard" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "hadolint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_detects_wildcard_ignore(self, tmp_path: Path):
        (tmp_path / ".hadolint.yml").write_text(WILDCARD_IGNORE_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "ignore_wildcard" for f in findings)

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = HadolintAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = HadolintFinding(
            kind="tagging_rule_ignored",
            severity="high",
            message="DL3006 ignored",
            path=".hadolint.yaml",
            lineno=4,
        )
        assert "[high] .hadolint.yaml:4" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = HadolintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "failure-threshold: warning" in template
        assert "strict-labels: true" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "hadolint analysis:" in context
        assert "health score:" in context
