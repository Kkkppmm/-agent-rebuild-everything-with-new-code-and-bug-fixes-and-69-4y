"""Tests for v6.92.0 ConsulAnalyzer integration."""

from pathlib import Path

from devai import ConsulAnalyzer, DevAI
from devai.project_health import ProjectHealth

HARDENED_CONSUL = """\
datacenter = "dc1"
data_dir   = "/opt/consul/data"

encrypt = "${CONSUL_GOSSIP_KEY}"

acl {
  enabled        = true
  default_policy = "deny"
}

tls {
  defaults {
    verify_incoming = true
    verify_outgoing = true
    ca_file         = "/etc/consul/tls/ca.pem"
    cert_file       = "/etc/consul/tls/server.pem"
    private_key_file = "/etc/consul/tls/server-key.pem"
  }
}

ports {
  http  = -1
  https = 8501
}

auto_encrypt {
  allow_tls = true
}

connect {
  enabled = true
}

ui_config {
  enabled = false
}

bind_addr   = "10.0.0.10"
client_addr = "127.0.0.1"
"""

UNSAFE_CONSUL = """\
dev_mode = true
datacenter = "dev"

acl {
  enabled        = false
  default_policy = "allow"
  tokens {
    agent = "12345678-1234-1234-1234-123456789abc"
  }
}

tls {
  defaults {
    verify_incoming = false
    verify_outgoing = false
  }
}

ports {
  https = -1
}

auto_encrypt {
  allow_tls = false
}

connect {
  enabled = false
}

ui_config {
  enabled = true
}

bind_addr    = "0.0.0.0"
client_addr  = "0.0.0.0"
retry_join   = "http://consul.internal:8500"
rpc_hold_timeout = "120s"
"""


class TestConsulAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        config = tmp_path / "consul.hcl"
        config.write_text(HARDENED_CONSUL, encoding="utf-8")
        analyzer = ConsulAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.health_score() == 100.0

    def test_detects_unsafe_config(self, tmp_path: Path):
        config = tmp_path / "consul.hcl"
        config.write_text(UNSAFE_CONSUL, encoding="utf-8")
        analyzer = ConsulAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "dev_mode" in kinds
        assert "acl_disabled" in kinds
        assert "acl_default_allow" in kinds
        assert "tls_verify_incoming_disabled" in kinds
        assert "https_disabled" in kinds
        assert "hardcoded_token" in kinds
        assert "missing_encrypt" in kinds
        assert analyzer.stats.high_severity >= 4
        assert analyzer.health_score() < 50.0

    def test_detects_missing_acl_and_encrypt(self, tmp_path: Path):
        config = tmp_path / "consul.hcl"
        config.write_text('datacenter = "prod"\ndata_dir = "/data"\n', encoding="utf-8")
        analyzer = ConsulAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "missing_acl" in kinds
        assert "missing_encrypt" in kinds

    def test_summary_and_context(self, tmp_path: Path):
        config = tmp_path / "consul.hcl"
        config.write_text(UNSAFE_CONSUL, encoding="utf-8")
        analyzer = ConsulAnalyzer(str(tmp_path))
        assert "Consul:" in analyzer.summary()
        assert "Consul config analysis" in analyzer.to_context()

    def test_hardened_template(self):
        template = ConsulAnalyzer(".").generate_hardened_template()
        assert 'default_policy = "deny"' in template
        assert "verify_incoming" in template
        assert "auto_encrypt" in template

    def test_devai_facade(self, tmp_path: Path):
        config = tmp_path / "consul.hcl"
        config.write_text(UNSAFE_CONSUL, encoding="utf-8")
        ai = DevAI.mock()
        analyzer = ai.consul(str(tmp_path))
        assert isinstance(analyzer, ConsulAnalyzer)
        assert analyzer.stats.findings > 0

    def test_project_health_integration(self, tmp_path: Path):
        config = tmp_path / "consul.hcl"
        config.write_text(UNSAFE_CONSUL, encoding="utf-8")
        health = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in health.categories}
        assert "consul" in names
        consul_cat = next(cat for cat in health.categories if cat.name == "consul")
        assert consul_cat.score < 100.0
