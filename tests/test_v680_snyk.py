"""Tests for v6.80.0 SnykAnalyzer integration."""

from pathlib import Path

from devai import DevAI, SnykAnalyzer
from devai.project_health import ProjectHealth


HARDENED_POLICY = """\
# Snyk (https://snyk.io) policy file
version: v1.25.0
ignore:
  SNYK-JS-LODASH-590103:
    - src/legacy/utils.js:
        reason: Legacy module scheduled for removal in Q3
        expires: 2026-06-30T00:00:00.000Z
patch: {}
"""

UNSAFE_POLICY = """\
version: v1.25.0
ignore:
  SNYK-JS-LODASH-590103:
    - '*':
        reason: ignore everything
  CVE-2024-1234:
    - '**':
token: snyk_abcd1234-5678-90ab-cdef-1234567890ab
severity-threshold: low
monitor: false
"""

UNSAFE_CLI = """\
version: v1.0.0
api: http://api.example.com/v1
token: ghp_abcdefghijklmnopqrstuvwxyz1234567890
ignoreUnknown: true
"""


class TestSnykAnalyzer:
    def test_finds_no_high_issues_in_hardened_policy(self, tmp_path: Path):
        (tmp_path / ".snyk").write_text(HARDENED_POLICY, encoding="utf-8")
        analyzer = SnykAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.stats.policy_files == 1

    def test_detects_unsafe_settings(self, tmp_path: Path):
        (tmp_path / ".snyk").write_text(UNSAFE_POLICY, encoding="utf-8")
        analyzer = SnykAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "broad_ignore" in kinds
        assert "hardcoded_secret" in kinds
        assert "low_severity_threshold" in kinds
        assert "alerts_disabled" in kinds

    def test_detects_cli_config_issues(self, tmp_path: Path):
        (tmp_path / "snyk.yaml").write_text(UNSAFE_CLI, encoding="utf-8")
        analyzer = SnykAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "ignore_unknown" in kinds
        assert analyzer.stats.cli_files == 1

    def test_facade_snyk(self, tmp_path: Path):
        (tmp_path / ".snyk").write_text(HARDENED_POLICY, encoding="utf-8")
        analyzer = DevAI.mock().snyk(tmp_path)
        assert isinstance(analyzer, SnykAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_snyk_category(self, tmp_path: Path):
        (tmp_path / ".snyk").write_text(HARDENED_POLICY, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "snyk" in names

    def test_generate_hardened_template(self):
        template = SnykAnalyzer(".").generate_hardened_template()
        assert "version:" in template
        assert "expires:" in template
