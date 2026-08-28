"""Tests for v6.93.0 NomadAnalyzer integration."""

from pathlib import Path

from devai import DevAI, NomadAnalyzer
from devai.project_health import ProjectHealth

HARDENED_NOMAD = """\
datacenter = "dc1"
data_dir   = "/opt/nomad/data"
region     = "global"

server {
  enabled = true
}

client {
  enabled = true
}

acl {
  enabled        = true
  default_policy = "deny"
}

tls {
  http                   = true
  rpc                    = true
  ca_file                = "/etc/nomad/tls/ca.pem"
  cert_file              = "/etc/nomad/tls/server.pem"
  key_file               = "/etc/nomad/tls/server-key.pem"
  verify_server_hostname = true
  verify_https_client    = true
}

vault {
  enabled = true
  address = "https://vault.service.consul:8200"
}

consul {
  address = "127.0.0.1:8501"
}

plugin "docker" {
  config {
    allow_privileged = false
  }
}

ui {
  enabled = false
}

bind_addr = "10.0.0.20"
"""

UNSAFE_NOMAD = """\
dev {
  enabled = true
}

datacenter = "dev"
data_dir   = "/tmp/nomad"
region     = "global"

server {
  enabled = true
}

client {
  enabled = true
}

acl {
  enabled        = false
  default_policy = "allow"
  tokens {
    management = "12345678-1234-1234-1234-123456789abc"
  }
}

tls {
  http                   = false
  rpc                    = false
  verify_server_hostname = false
  verify_https_client    = false
}

consul {
  address = "http://consul.internal:8500"
}

plugin "docker" {
  config {
    allow_privileged = true
  }
}

plugin "raw_exec" {
  config {
    enabled = true
  }
}

host_volume "data" {
  path    = "/var/data"
  read_only = false
  enabled = true
}

ui {
  enabled = true
}

bind_addr = "0.0.0.0"
"""


class TestNomadAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        config = tmp_path / "nomad.hcl"
        config.write_text(HARDENED_NOMAD, encoding="utf-8")
        analyzer = NomadAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.health_score() == 100.0

    def test_detects_unsafe_config(self, tmp_path: Path):
        config = tmp_path / "nomad.hcl"
        config.write_text(UNSAFE_NOMAD, encoding="utf-8")
        analyzer = NomadAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "dev_block" in kinds
        assert "acl_disabled" in kinds
        assert "acl_default_allow" in kinds
        assert "tls_http_disabled" in kinds
        assert "tls_rpc_disabled" in kinds
        assert "allow_privileged" in kinds
        assert "raw_exec_enabled" in kinds
        assert "hardcoded_token" in kinds
        assert "insecure_http" in kinds
        assert analyzer.stats.high_severity >= 5
        assert analyzer.health_score() < 50.0

    def test_detects_missing_acl_and_tls(self, tmp_path: Path):
        config = tmp_path / "nomad.hcl"
        config.write_text(
            'datacenter = "prod"\ndata_dir = "/data"\nregion = "global"\n',
            encoding="utf-8",
        )
        analyzer = NomadAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "missing_acl" in kinds
        assert "missing_tls" in kinds

    def test_summary_and_context(self, tmp_path: Path):
        config = tmp_path / "nomad.hcl"
        config.write_text(UNSAFE_NOMAD, encoding="utf-8")
        analyzer = NomadAnalyzer(str(tmp_path))
        assert "Nomad:" in analyzer.summary()
        assert "Nomad config analysis" in analyzer.to_context()

    def test_hardened_template(self):
        template = NomadAnalyzer(".").generate_hardened_template()
        assert 'default_policy = "deny"' in template
        assert "verify_server_hostname" in template
        assert "allow_privileged = false" in template

    def test_devai_facade(self, tmp_path: Path):
        config = tmp_path / "nomad.hcl"
        config.write_text(UNSAFE_NOMAD, encoding="utf-8")
        ai = DevAI.mock()
        analyzer = ai.nomad(str(tmp_path))
        assert isinstance(analyzer, NomadAnalyzer)
        assert analyzer.stats.findings > 0

    def test_project_health_integration(self, tmp_path: Path):
        config = tmp_path / "nomad.hcl"
        config.write_text(UNSAFE_NOMAD, encoding="utf-8")
        health = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in health.categories}
        assert "nomad" in names
        nomad_cat = next(cat for cat in health.categories if cat.name == "nomad")
        assert nomad_cat.score < 100.0
