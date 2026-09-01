"""Tests for v6.91.0 VaultAnalyzer integration."""

from pathlib import Path

from devai import DevAI, VaultAnalyzer
from devai.project_health import ProjectHealth

HARDENED_VAULT = """\
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "node1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/etc/vault/tls/vault.crt"
  tls_key_file    = "/etc/vault/tls/vault.key"
  tls_min_version = "tls12"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/vault-unseal"
}

api_addr     = "https://vault.example.com:8200"
cluster_addr = "https://vault.example.com:8201"

ui                   = false
disable_mlock        = false
default_lease_ttl    = "1h"
max_lease_ttl        = "24h"
raw_storage_endpoint = false
"""

UNSAFE_VAULT = """\
dev {
  dev_root_token_id = "root-token-12345"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

storage "file" {
  path = "/tmp/vault-data"
}

api_addr     = "http://vault.internal:8200"
cluster_addr = "http://vault.internal:8201"
ui           = true
disable_mlock = true
raw_storage_endpoint = true
default_lease_ttl = "8760h"
plugin_directory = "/tmp/vault-plugins"
"""


class TestVaultAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        config = tmp_path / "vault.hcl"
        config.write_text(HARDENED_VAULT, encoding="utf-8")
        analyzer = VaultAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.stats.findings == 0
        assert analyzer.health_score() == 100.0

    def test_detects_unsafe_config(self, tmp_path: Path):
        config = tmp_path / "vault.hcl"
        config.write_text(UNSAFE_VAULT, encoding="utf-8")
        analyzer = VaultAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "dev_mode" in kinds
        assert "tls_disabled" in kinds
        assert "insecure_http" in kinds
        assert "raw_storage_endpoint" in kinds
        assert analyzer.stats.high_severity >= 3
        assert analyzer.health_score() < 50.0

    def test_detects_missing_seal(self, tmp_path: Path):
        config = tmp_path / "config.hcl"
        config.write_text(
            'storage "raft" {\n  path = "/data"\n}\n'
            'listener "tcp" {\n  tls_cert_file = "/c.crt"\n  tls_key_file = "/c.key"\n}\n',
            encoding="utf-8",
        )
        analyzer = VaultAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "missing_seal" in kinds

    def test_summary_and_context(self, tmp_path: Path):
        config = tmp_path / "vault.hcl"
        config.write_text(UNSAFE_VAULT, encoding="utf-8")
        analyzer = VaultAnalyzer(str(tmp_path))
        assert "Vault:" in analyzer.summary()
        assert "Vault config analysis" in analyzer.to_context()

    def test_hardened_template(self):
        template = VaultAnalyzer(".").generate_hardened_template()
        assert 'storage "raft"' in template
        assert "tls_cert_file" in template
        assert 'seal "awskms"' in template

    def test_devai_facade(self, tmp_path: Path):
        config = tmp_path / "vault.hcl"
        config.write_text(UNSAFE_VAULT, encoding="utf-8")
        ai = DevAI.mock()
        analyzer = ai.vault(str(tmp_path))
        assert isinstance(analyzer, VaultAnalyzer)
        assert analyzer.stats.findings > 0

    def test_project_health_integration(self, tmp_path: Path):
        config = tmp_path / "vault.hcl"
        config.write_text(UNSAFE_VAULT, encoding="utf-8")
        health = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in health.categories}
        assert "vault" in names
        vault_cat = next(cat for cat in health.categories if cat.name == "vault")
        assert vault_cat.score < 100.0
