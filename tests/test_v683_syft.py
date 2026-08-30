"""Tests for v6.83.0 SyftAnalyzer integration."""

from pathlib import Path

from devai import DevAI, SyftAnalyzer
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """\
output: cyclonedx-json
file:
  metadata:
    selection: all
registry:
  insecure-skip-tls-verify: false
attest:
  enabled: true
exclude:
  - path: /tmp/build-cache
"""

UNSAFE_CONFIG = """\
output: table
registry:
  auth:
    token: supersecret123
  url: http://registry.example.com/v2/
  insecure-skip-tls-verify: true
  endpoint: http://proxy.example.com:8080
attest: false
verify-signature: false
exclude-everything: true
exclude:
  - "**"
  - /*
catalogers: []
token: ghp_abcdefghijklmnopqrstuvwxyz1234567890
"""


class TestSyftAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        (tmp_path / ".syft.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = SyftAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1

    def test_detects_unsafe_config_patterns(self, tmp_path: Path):
        (tmp_path / ".syft.yaml").write_text(UNSAFE_CONFIG, encoding="utf-8")
        analyzer = SyftAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "insecure_tls" in kinds
        assert "registry_credentials" in kinds
        assert "broad_exclude" in kinds
        assert "disabled_attest" in kinds
        assert "disabled_signature" in kinds
        assert "empty_catalogers" in kinds
        assert "non_machine_output" in kinds

    def test_facade_syft(self):
        analyzer = DevAI.mock().syft(".")
        assert isinstance(analyzer, SyftAnalyzer)

    def test_project_health_includes_syft_category(self, tmp_path: Path):
        (tmp_path / ".syft.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "syft" in names

    def test_generate_hardened_template(self):
        template = SyftAnalyzer(".").generate_hardened_template()
        assert "cyclonedx-json" in template
        assert "insecure-skip-tls-verify: false" in template

    def test_syft_config_in_subdirectory(self, tmp_path: Path):
        syft_dir = tmp_path / "syft"
        syft_dir.mkdir()
        (syft_dir / "config.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = SyftAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_to_context_includes_health_score(self, tmp_path: Path):
        (tmp_path / "syft.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = SyftAnalyzer(str(tmp_path)).to_context()
        assert "health score:" in context
        assert "Syft config analysis:" in context
