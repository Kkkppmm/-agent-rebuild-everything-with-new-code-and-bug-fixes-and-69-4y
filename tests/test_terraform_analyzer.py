"""Tests for TerraformAnalyzer."""

from pathlib import Path

from devai.terraform_analyzer import TerraformAnalyzer, TerraformFinding


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
  password             = "hardcodedpassword123"
  skip_final_snapshot  = true
}
"""

HARDENED_TF = """
resource "aws_s3_bucket" "app" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_public_access_block" "app" {
  bucket                  = aws_s3_bucket.app.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""


class TestTerraformAnalyzer:
    def test_no_terraform_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        assert analyzer.stats.terraform_files == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(INSECURE_TF, encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "open_security_group" in kinds
        assert "public_s3_acl" in kinds
        assert "hardcoded_secret" in kinds
        assert "skip_final_snapshot" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_terraform_scores_well(self, tmp_path: Path):
        (tmp_path / "s3.tf").write_text(HARDENED_TF, encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity in ("high", "critical") for f in findings)
        assert analyzer.stats.terraform_files == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(HARDENED_TF, encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        assert "Terraform" in analyzer.summary()
        assert "Terraform analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "block_public_acls" in template

    def test_finding_format(self):
        finding = TerraformFinding(
            kind="open_security_group",
            severity="high",
            message="open SG",
            path="main.tf",
            lineno=3,
        )
        assert "main.tf:3" in finding.format()
