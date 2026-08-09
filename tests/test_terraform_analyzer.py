"""Tests for TerraformAnalyzer."""

from pathlib import Path

from devai.terraform_analyzer import TerraformAnalyzer


INSECURE_TF = """
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 22
    to_port     = 22
  }
}

resource "aws_s3_bucket" "data" {
  acl = "public-read"
}

resource "aws_db_instance" "db" {
  password             = "supersecret"
  skip_final_snapshot  = true
  encrypted            = false
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Resource = "*"
    }]
  })
}
"""

HARDENED_TF = """
terraform {
  required_version = "1.9.0"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket            = aws_s3_bucket.data.id
  block_public_acls = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
"""


class TestTerraformAnalyzer:
    def test_no_terraform_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        assert analyzer.stats.terraform_files == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        infra = tmp_path / "infra"
        infra.mkdir()
        (infra / "main.tf").write_text(INSECURE_TF, encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "open_security_group" in kinds
        assert "public_s3_acl" in kinds
        assert "hardcoded_secret" in kinds
        assert "skip_final_snapshot" in kinds
        assert "unencrypted_ebs" in kinds
        assert analyzer.health_score() < 30.0

    def test_hardened_terraform_scores_well(self, tmp_path: Path):
        (tmp_path / "secure.tf").write_text(HARDENED_TF, encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(HARDENED_TF, encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        assert "Terraform files:" in analyzer.summary()
        assert "Terraform analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "block_public_acls" in template
