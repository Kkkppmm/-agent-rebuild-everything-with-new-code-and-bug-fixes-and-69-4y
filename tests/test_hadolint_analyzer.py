"""Tests for HadolintAnalyzer."""

from pathlib import Path

from devai.hadolint_analyzer import HadolintAnalyzer, HadolintFinding

HARDENED_CONFIG = """\
# Hadolint hardened config
failure-threshold: warning
format: tty
ignored: []
"""

INSECURE_CONFIG = """\
failure-threshold: info
ignored:
  - all
  - DL3002
  - DL3007
  - DL3008
  - DL3013
  - DL3020
  - DL3027
  - DL3004
  - DL3046
  - DL3018
  - DL3028
trustedRegistries:
  - http://insecure-registry.example.com
api_key=supersecret123
AKIAIOSFODNN7EXAMPLE
curl http://example.com/install.sh | bash
"""


class TestHadolintAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "ignore_all" in kinds
        assert "root_user_ignored" in kinds
        assert "version_pin_ignored" in kinds
        assert "add_copy_ignored" in kinds
        assert "upgrade_ignored" in kinds
        assert "sudo_ignored" in kinds
        assert "permissive_threshold" in kinds
        assert "insecure_registry" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds
        assert "many_ignored" in kinds
        assert "many_security_ignored" in kinds
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

    def test_hadolint_yml_variant(self, tmp_path: Path):
        (tmp_path / "hadolint.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = HadolintAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_generate_hardened_template(self):
        template = HadolintAnalyzer(".").generate_hardened_template()
        assert "failure-threshold: warning" in template
        assert "ignored: []" in template

    def test_wildcard_ignore(self, tmp_path: Path):
        config = "ignored:\n  - DL30*\n"
        (tmp_path / ".hadolint.yaml").write_text(config, encoding="utf-8")
        kinds = {f.kind for f in HadolintAnalyzer(str(tmp_path)).analyze()}
        assert "wildcard_ignore" in kinds
