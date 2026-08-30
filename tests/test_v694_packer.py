"""Tests for v6.94.0 PackerAnalyzer integration."""

from pathlib import Path

from devai import DevAI, PackerAnalyzer
from devai.project_health import ProjectHealth

HARDENED_PACKER = """\
packer {
  required_version = ">= 1.9.0"
}

variable "source_ami" {
  type = string
}

source "amazon-ebs" "hardened" {
  region        = "us-east-1"
  source_ami    = var.source_ami
  instance_type = "t3.small"
  ssh_username  = "ec2-user"
  encrypt_boot  = true
  ami_name      = "hardened-{{timestamp}}"
}

build {
  sources = ["source.amazon-ebs.hardened"]

  provisioner "shell" {
    inline = [
      "sudo dnf update -y",
    ]
  }
}
"""

UNSAFE_PACKER = """\
source "amazon-ebs" "unsafe" {
  region                  = "us-east-1"
  source_ami              = "ami-0abcdef1234567890"
  instance_type           = "t3.micro"
  ssh_username            = "ubuntu"
  ssh_password            = "SuperSecret123!"
  access_key              = "AKIAIOSFODNN7EXAMPLE"
  secret_key              = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  encrypt_boot            = false
  ami_name                = "unsafe-{{timestamp}}"
  force_deregister        = true
}

source "docker" "unsafe" {
  image       = "ubuntu:latest"
  privileged  = true
}

build {
  sources = ["source.amazon-ebs.unsafe", "source.docker.unsafe"]

  provisioner "shell" {
    inline = [
      "curl https://install.example.com/script.sh | bash",
    ]
    run_as = "root"
  }

  provisioner "shell" {
    environment_vars = {
      API_KEY = "sk-live-1234567890abcdef"
      password = "plaintext-db-pass"
    }
    inline = ["echo done"]
  }
}

source "qemu" "iso" {
  iso_url      = "http://mirror.example.com/ubuntu.iso"
  skip_checksum  = true
}
"""


class TestPackerAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        config = tmp_path / "packer.pkr.hcl"
        config.write_text(HARDENED_PACKER, encoding="utf-8")
        analyzer = PackerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.health_score() == 100.0

    def test_detects_unsafe_config(self, tmp_path: Path):
        config = tmp_path / "packer.pkr.hcl"
        config.write_text(UNSAFE_PACKER, encoding="utf-8")
        analyzer = PackerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "ssh_password" in kinds
        assert "hardcoded_aws_key" in kinds
        assert "hardcoded_secret" in kinds
        assert "latest_tag" in kinds
        assert "curl_pipe_shell" in kinds
        assert "encrypt_boot_disabled" in kinds
        assert "privileged_docker" in kinds
        assert "insecure_http" in kinds
        assert "missing_checksum" in kinds
        assert "plaintext_env_secret" in kinds
        assert analyzer.stats.high_severity >= 5
        assert analyzer.health_score() < 50.0

    def test_detects_missing_build(self, tmp_path: Path):
        config = tmp_path / "image.pkr.hcl"
        config.write_text(
            'source "amazon-ebs" "orphan" {\n  region = "us-east-1"\n}\n',
            encoding="utf-8",
        )
        analyzer = PackerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "missing_build" in kinds

    def test_summary_and_context(self, tmp_path: Path):
        config = tmp_path / "packer.pkr.hcl"
        config.write_text(UNSAFE_PACKER, encoding="utf-8")
        analyzer = PackerAnalyzer(str(tmp_path))
        assert "Packer:" in analyzer.summary()
        assert "Packer config analysis" in analyzer.to_context()

    def test_hardened_template(self):
        template = PackerAnalyzer(".").generate_hardened_template()
        assert "encrypt_boot" in template
        assert "force_deregister        = false" in template
        assert "required_version" in template

    def test_devai_facade(self, tmp_path: Path):
        config = tmp_path / "packer.pkr.hcl"
        config.write_text(UNSAFE_PACKER, encoding="utf-8")
        ai = DevAI.mock()
        analyzer = ai.packer(str(tmp_path))
        assert isinstance(analyzer, PackerAnalyzer)
        assert analyzer.stats.findings > 0

    def test_project_health_integration(self, tmp_path: Path):
        config = tmp_path / "packer.pkr.hcl"
        config.write_text(UNSAFE_PACKER, encoding="utf-8")
        health = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in health.categories}
        assert "packer" in names
        packer_cat = next(cat for cat in health.categories if cat.name == "packer")
        assert packer_cat.score < 100.0
