"""Tests for TerraformAnalyzer."""

from pathlib import Path

from devai.terraform_analyzer import TerraformAnalyzer, TerraformFinding


GOOD_S3 = """\
resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""


class TestTerraformAnalyzer:
    def test_no_files_returns_empty(self, tmp_path: Path):
        analyzer = TerraformAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary().lower()

    def test_clean_s3_config(self, tmp_path: Path):
        tf_dir = tmp_path / "terraform"
        tf_dir.mkdir()
        (tf_dir / "main.tf").write_text(GOOD_S3, encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not findings
        stats = analyzer.stats
        assert stats.files == 1
        assert stats.resources >= 1
        assert analyzer.health_score() == 100.0

    def test_detects_open_security_group(self, tmp_path: Path):
        tf_dir = tmp_path / "infra"
        tf_dir.mkdir()
        (tf_dir / "security.tf").write_text(
            'resource "aws_security_group_rule" "ingress" {\n'
            "  cidr_blocks = [\"0.0.0.0/0\"]\n"
            "}\n",
            encoding="utf-8",
        )
        findings = TerraformAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "open_security_group" for f in findings)

    def test_detects_public_s3_acl(self, tmp_path: Path):
        tf_dir = tmp_path / "terraform"
        tf_dir.mkdir()
        (tf_dir / "s3.tf").write_text(
            'resource "aws_s3_bucket_acl" "data" {\n  acl = "public-read"\n}\n',
            encoding="utf-8",
        )
        findings = TerraformAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "public_s3_acl" for f in findings)

    def test_detects_encryption_disabled(self, tmp_path: Path):
        tf_dir = tmp_path / "terraform"
        tf_dir.mkdir()
        (tf_dir / "rds.tf").write_text(
            'resource "aws_db_instance" "db" {\n  storage_encrypted = false\n}\n',
            encoding="utf-8",
        )
        findings = TerraformAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "encryption_disabled" for f in findings)

    def test_detects_hardcoded_secret(self, tmp_path: Path):
        tf_dir = tmp_path / "terraform"
        tf_dir.mkdir()
        (tf_dir / "secrets.tf").write_text(
            'password = "supersecretpassword123"\n',
            encoding="utf-8",
        )
        findings = TerraformAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "hardcoded_secret" for f in findings)

    def test_detects_wildcard_iam(self, tmp_path: Path):
        tf_dir = tmp_path / "terraform"
        tf_dir.mkdir()
        (tf_dir / "iam.tf").write_text(
            'resource "aws_iam_policy" "admin" {\n'
            '  policy = jsonencode({ Action = "*", Resource = "*" })\n'
            "}\n",
            encoding="utf-8",
        )
        findings = TerraformAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "wildcard_iam_action" for f in findings)
        assert any(f.kind == "wildcard_iam_resource" for f in findings)

    def test_finding_format(self):
        finding = TerraformFinding(
            kind="test",
            severity="high",
            message="msg",
            path="terraform/main.tf",
            lineno=5,
            resource="aws_s3_bucket.data",
        )
        assert "aws_s3_bucket.data" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        template = TerraformAnalyzer(str(tmp_path)).generate_hardened_template()
        assert "block_public_acls" in template
        assert 'acl    = "private"' in template

    def test_to_context(self, tmp_path: Path):
        tf_dir = tmp_path / "terraform"
        tf_dir.mkdir()
        (tf_dir / "main.tf").write_text(
            'resource "aws_s3_bucket_acl" "x" {\n  acl = "public-read-write"\n}\n',
            encoding="utf-8",
        )
        context = TerraformAnalyzer(str(tmp_path)).to_context()
        assert "Terraform analysis" in context
        assert "public" in context.lower()
