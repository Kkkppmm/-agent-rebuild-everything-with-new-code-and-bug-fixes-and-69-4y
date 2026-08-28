"""Tests for HadolintAnalyzer."""

from pathlib import Path

from devai.hadolint_analyzer import HadolintAnalyzer, HadolintFinding


INSECURE_CONFIG = """\
failure-threshold: info

ignored:
  - DL3002
  - DL3006
  - DL3007
  - DL3008
  - DL3013
  - DL3018
  - SC2086
  - SC2046
  - SC2154
  - DL3025

trustedRegistries:
  - "*"
  - http://insecure-registry.example.com

api_key: hardcoded_secret_value_12345
"""

HARDENED_CONFIG = """\
failure-threshold: warning

# Only ignore rules with documented justification:
# ignored:
#   - DL3008

trustedRegistries:
  - docker.io
  - ghcr.io
"""


class TestHadolintAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "failure_threshold_low" in kinds
        assert "ignore_security_rule" in kinds
        assert "trusted_registry_wildcard" in kinds
        assert "trusted_registry_http" in kinds
        assert "hardcoded_secret" in kinds
        assert "many_ignored_rules" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".hadolint.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].failure_threshold == "warning"
        assert "docker.io" in analyzer.infos[0].trusted_registries

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = HadolintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = HadolintFinding(
            kind="ignore_all",
            severity="high",
            message="ignoring all Hadolint rules",
            path=".hadolint.yaml",
            lineno=4,
            line="  - *",
        )
        assert "[high] .hadolint.yaml:4" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = HadolintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "failure-threshold: warning" in template
        assert "trustedRegistries:" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        assert "1 file(s)" in analyzer.summary()
        context = analyzer.to_context()
        assert "hadolint analysis:" in context
        assert "health score:" in context
