"""Tests for v6.96.0 TerragruntAnalyzer integration."""

from pathlib import Path

from devai import DevAI, TerragruntAnalyzer
from devai.project_health import ProjectHealth

HARDENED_TERRAGRUNT = """\
remote_state {
  backend = "s3"
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
  config = {
    bucket         = get_env("TG_STATE_BUCKET", "my-org-terraform-state")
    key            = "${path_relative_to_include()}/terraform.tfstate"
    region         = get_env("AWS_REGION", "us-east-1")
    encrypt        = true
    dynamodb_table = get_env("TG_LOCK_TABLE", "terraform-locks")
  }
}

terraform {
  source = "git::https://github.com/gruntwork-io/terraform-aws-vpc.git?ref=v3.19.0"
}

inputs = {
  aws_region = get_env("AWS_REGION", "us-east-1")
}
"""

UNSAFE_TERRAGRUNT = """\
remote_state {
  backend = "http"
  config = {
    address = "http://terraform-state.example.com"
  }
}

terraform {
  source = "git::https://github.com/example/insecure-module.git"
}

dependency "vpc" {
  config_path = "../vpc"
  mock_outputs = {
    vpc_id = "mock-vpc-id"
  }
  mock_outputs_allowed_terraform_commands = []
  skip_outputs = true
}

inputs = {
  db_password = "SuperSecret123!"
  api_key     = "sk-live-1234567890abcdef"
  aws_access_key_id     = "AKIAIOSFODNN7EXAMPLE"
  aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

iam_role = "arn:aws:iam::*:role/*"

generate "provider" {
  path = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
EOF
}

prevent_destroy = false
skip_bucket_versioning = true
disable_bucket_update = true

locals {
  bootstrap = "curl https://install.example.com/script.sh | bash"
}
"""


class TestTerragruntAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        config = tmp_path / "terragrunt.hcl"
        config.write_text(HARDENED_TERRAGRUNT, encoding="utf-8")
        analyzer = TerragruntAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.health_score() == 100.0

    def test_detects_unsafe_config(self, tmp_path: Path):
        config = tmp_path / "terragrunt.hcl"
        config.write_text(UNSAFE_TERRAGRUNT, encoding="utf-8")
        analyzer = TerragruntAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http_backend" in kinds
        assert "hardcoded_secret" in kinds
        assert "hardcoded_aws_key" in kinds
        assert "generated_credential" in kinds
        assert "wildcard_iam_role" in kinds
        assert "mock_outputs" in kinds
        assert "mock_outputs_unrestricted" in kinds
        assert "unpinned_module_source" in kinds
        assert "prevent_destroy_disabled" in kinds
        assert "skip_bucket_versioning" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.stats.high_severity >= 5
        assert analyzer.health_score() < 50.0

    def test_summary_and_context(self, tmp_path: Path):
        config = tmp_path / "terragrunt.hcl"
        config.write_text(UNSAFE_TERRAGRUNT, encoding="utf-8")
        analyzer = TerragruntAnalyzer(str(tmp_path))
        assert "Terragrunt:" in analyzer.summary()
        assert "Terragrunt config analysis" in analyzer.to_context()

    def test_hardened_template(self):
        template = TerragruntAnalyzer(".").generate_hardened_template()
        assert "encrypt        = true" in template
        assert "dynamodb_table" in template
        assert "?ref=" in template

    def test_devai_facade(self, tmp_path: Path):
        config = tmp_path / "terragrunt.hcl"
        config.write_text(UNSAFE_TERRAGRUNT, encoding="utf-8")
        ai = DevAI.mock()
        analyzer = ai.terragrunt(str(tmp_path))
        assert isinstance(analyzer, TerragruntAnalyzer)
        assert analyzer.stats.findings > 0

    def test_project_health_integration(self, tmp_path: Path):
        config = tmp_path / "terragrunt.hcl"
        config.write_text(UNSAFE_TERRAGRUNT, encoding="utf-8")
        health = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in health.categories}
        assert "terragrunt" in names
        tg_cat = next(cat for cat in health.categories if cat.name == "terragrunt")
        assert tg_cat.score < 100.0

    def test_detects_missing_remote_state(self, tmp_path: Path):
        config = tmp_path / "terragrunt.hcl"
        config.write_text(
            'terraform {\n  source = "git::https://github.com/example/mod.git?ref=v1.0.0"\n}\n',
            encoding="utf-8",
        )
        analyzer = TerragruntAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "missing_remote_state" in kinds

    def test_detects_missing_state_lock(self, tmp_path: Path):
        config = tmp_path / "terragrunt.hcl"
        config.write_text(
            """\
remote_state {
  backend = "s3"
  config = {
    bucket  = "my-state"
    key     = "prod/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}
""",
            encoding="utf-8",
        )
        analyzer = TerragruntAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "missing_state_lock" in kinds
