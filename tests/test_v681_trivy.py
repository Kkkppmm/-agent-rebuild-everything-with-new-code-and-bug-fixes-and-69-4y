"""Tests for v6.81.0 TrivyAnalyzer integration."""

from pathlib import Path

from devai import DevAI, TrivyAnalyzer
from devai.project_health import ProjectHealth


HARDENED_IGNORE = """\
# Accepted risk — tracked in SEC-456, expires 2026-09-01
CVE-2024-12345
GHSA-xxxx-yyyy-zzzz
"""

UNSAFE_IGNORE = """\
*
CVE-*
GHSA-abcd-efgh-ijkl
token: ghp_abcdefghijklmnopqrstuvwxyz1234567890
"""

HARDENED_CONFIG = """\
scan:
  severity:
    - CRITICAL
    - HIGH
    - MEDIUM
  exit-code: 1
  ignore-unfixed: false
db:
  skip-update: false
"""

UNSAFE_CONFIG = """\
scan:
  severity:
    - UNKNOWN
    - LOW
  exit-code: 0
  ignore-unfixed: true
  skip-dirs:
    - "**"
  insecure: true
db:
  repository: http://vuln-db.example.com/trivy-db
  skip-update: true
registry:
  credentials:
    username: admin
    password: supersecret123
"""


class TestTrivyAnalyzer:
    def test_finds_no_high_issues_in_hardened_ignore(self, tmp_path: Path):
        (tmp_path / ".trivyignore").write_text(HARDENED_IGNORE, encoding="utf-8")
        analyzer = TrivyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.stats.ignore_files == 1

    def test_detects_unsafe_ignore_patterns(self, tmp_path: Path):
        (tmp_path / ".trivyignore").write_text(UNSAFE_IGNORE, encoding="utf-8")
        analyzer = TrivyAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "broad_ignore" in kinds
        assert "hardcoded_secret" in kinds

    def test_detects_cli_config_issues(self, tmp_path: Path):
        (tmp_path / "trivy.yaml").write_text(UNSAFE_CONFIG, encoding="utf-8")
        analyzer = TrivyAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "fail_open" in kinds
        assert "insecure_http" in kinds
        assert "insecure_tls" in kinds
        assert "ignore_unfixed" in kinds
        assert "stale_db" in kinds
        assert "broad_skip" in kinds
        assert "low_severity_threshold" in kinds
        assert "registry_credentials" in kinds
        assert analyzer.stats.cli_files == 1

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "trivy.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = TrivyAnalyzer(str(tmp_path))
        high = [f for f in analyzer.analyze() if f.severity == "high"]
        assert high == []

    def test_facade_trivy(self, tmp_path: Path):
        (tmp_path / ".trivyignore").write_text(HARDENED_IGNORE, encoding="utf-8")
        analyzer = DevAI.mock().trivy(tmp_path)
        assert isinstance(analyzer, TrivyAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_trivy_category(self, tmp_path: Path):
        (tmp_path / ".trivyignore").write_text(HARDENED_IGNORE, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "trivy" in names

    def test_generate_hardened_template(self):
        template = TrivyAnalyzer(".").generate_hardened_template()
        assert "exit-code: 1" in template
        assert "CRITICAL" in template
