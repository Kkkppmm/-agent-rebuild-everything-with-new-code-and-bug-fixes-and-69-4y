"""Tests for v6.82.0 GrypeAnalyzer integration."""

from pathlib import Path

from devai import DevAI, GrypeAnalyzer
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
check:
  fail-on-severity: high
  only-fixed: false
db:
  auto-update: true
  validate-age: true
  validate-age-hours: 24
"""

UNSAFE_CONFIG = """\
check:
  fail-on-severity: none
  only-fixed: true
  match-everything: true
db:
  auto-update: false
  validate-age: false
  http-proxy: http://proxy.example.com:8080
  insecure-skip-tls-verify: true
registry:
  auth:
    token: supersecret123
ignore:
  - vulnerability: CVE-*
  - vulnerability: GHSA-abcd-efgh-ijkl
"""


class TestGrypeAnalyzer:
    def test_finds_no_high_issues_in_hardened_ignore(self, tmp_path: Path):
        (tmp_path / ".grypeignore").write_text(HARDENED_IGNORE, encoding="utf-8")
        analyzer = GrypeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.stats.ignore_files == 1

    def test_detects_unsafe_ignore_patterns(self, tmp_path: Path):
        (tmp_path / ".grypeignore").write_text(UNSAFE_IGNORE, encoding="utf-8")
        analyzer = GrypeAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "broad_ignore" in kinds
        assert "hardcoded_secret" in kinds

    def test_detects_cli_config_issues(self, tmp_path: Path):
        (tmp_path / ".grype.yaml").write_text(UNSAFE_CONFIG, encoding="utf-8")
        analyzer = GrypeAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "fail_open" in kinds
        assert "insecure_http" in kinds
        assert "insecure_tls" in kinds
        assert "stale_db" in kinds
        assert "registry_credentials" in kinds
        assert "broad_ignore" in kinds
        assert "only_fixed" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / ".grype.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = GrypeAnalyzer(str(tmp_path))
        high = [f for f in analyzer.analyze() if f.severity == "high"]
        assert high == []

    def test_facade_grype(self):
        analyzer = DevAI.mock().grype(".")
        assert isinstance(analyzer, GrypeAnalyzer)

    def test_project_health_includes_grype_category(self, tmp_path: Path):
        (tmp_path / ".grype.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "grype" in names

    def test_generate_hardened_template(self):
        template = GrypeAnalyzer(".").generate_hardened_template()
        assert "fail-on-severity: high" in template
        assert "auto-update: true" in template

    def test_grype_config_in_subdirectory(self, tmp_path: Path):
        grype_dir = tmp_path / "grype"
        grype_dir.mkdir()
        (grype_dir / "config.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = GrypeAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
        assert analyzer.stats.cli_files == 1
