"""Tests for HadolintAnalyzer."""

from pathlib import Path

from devai.hadolint_analyzer import HadolintAnalyzer, HadolintFinding

HARDENED_CONFIG = """\
failure-threshold: warning

ignored: []

trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io
"""

INSECURE_CONFIG = """\
failure-threshold: style
override: error

ignored:
  - '*'
  - DL3002
  - DL3006
  - DL3008
  - DL3013

trustedRegistries:
  - '*'
  - http://insecure-registry.local

api_key=supersecret123
AKIAIOSFODNN7EXAMPLE
curl http://example.com/install.sh | bash
"""


class TestHadolintAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "failure_threshold_style" in kinds
        assert "override_error" in kinds
        assert "ignore_all" in kinds
        assert "security_rule_ignored" in kinds
        assert "trusted_registry_all" in kinds
        assert "insecure_registry" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.stats.config_files == 1

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = HadolintAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = HadolintFinding(
            kind="ignore_all",
            severity="high",
            message="test message",
            path=".hadolint.yaml",
            lineno=3,
        )
        assert ".hadolint.yaml:3" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = HadolintAnalyzer(str(tmp_path)).to_context()
        assert "Hadolint config analysis" in context
        assert "health score" in context

    def test_generate_template(self):
        template = HadolintAnalyzer(".").generate_hardened_template()
        assert "failure-threshold: warning" in template
