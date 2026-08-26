"""Tests for v6.84.0 CosignAnalyzer integration."""

from pathlib import Path

from devai import CosignAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """\
registry:
  insecure-skip-tls-verify: false
require-signature: true
attest: true
rekor-url: https://rekor.sigstore.dev
policy:
  authorities:
    - key:
        data: |
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
          -----END PUBLIC KEY-----
"""

UNSAFE_CONFIG = """\
registry:
  auth:
    token: supersecret123
  url: http://registry.example.com/v2/
  insecure-skip-tls-verify: true
  endpoint: http://proxy.example.com:8080
insecure-ignore-tlog: true
insecure-ignore-sct: true
allow-insecure-registry: true
require-signature: false
attest: false
deny: false
match: "*"
algorithm: rsa-1024
private-key: |
  -----BEGIN PRIVATE KEY-----
  MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
  -----END PRIVATE KEY-----
token: ghp_abcdefghijklmnopqrstuvwxyz1234567890
rekor-url:
"""


class TestCosignAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        (tmp_path / ".cosign.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = CosignAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1

    def test_detects_unsafe_config_patterns(self, tmp_path: Path):
        (tmp_path / ".cosign.yaml").write_text(UNSAFE_CONFIG, encoding="utf-8")
        analyzer = CosignAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "hardcoded_secret" in kinds
        assert "inline_private_key" in kinds
        assert "insecure_http" in kinds
        assert "insecure_tls" in kinds
        assert "registry_credentials" in kinds
        assert "ignore_tlog" in kinds
        assert "ignore_sct" in kinds
        assert "insecure_registry" in kinds
        assert "disabled_signature" in kinds
        assert "disabled_attest" in kinds
        assert "permissive_policy" in kinds
        assert "wildcard_policy" in kinds
        assert "weak_key_algorithm" in kinds
        assert "missing_rekor" in kinds

    def test_facade_cosign(self):
        analyzer = DevAI.mock().cosign(".")
        assert isinstance(analyzer, CosignAnalyzer)

    def test_project_health_includes_cosign_category(self, tmp_path: Path):
        (tmp_path / ".cosign.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "cosign" in names

    def test_generate_hardened_template(self):
        template = CosignAnalyzer(".").generate_hardened_template()
        assert "insecure-skip-tls-verify: false" in template
        assert "rekor.sigstore.dev" in template

    def test_cosign_config_in_subdirectory(self, tmp_path: Path):
        cosign_dir = tmp_path / "cosign"
        cosign_dir.mkdir()
        (cosign_dir / "config.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = CosignAnalyzer(str(tmp_path))
        assert len(analyzer.files()) == 1
        assert analyzer.stats.configs == 1

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".cosign.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = CosignAnalyzer(str(tmp_path)).to_context()
        assert "Cosign config analysis" in context
        assert "health score" in context

    def test_policy_file_detection(self, tmp_path: Path):
        policy_dir = tmp_path / "policy"
        policy_dir.mkdir()
        (policy_dir / "policy.cue").write_text(
            'deny: false\nmatch: "*"\n',
            encoding="utf-8",
        )
        analyzer = CosignAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "permissive_policy" in kinds
        assert "wildcard_policy" in kinds
