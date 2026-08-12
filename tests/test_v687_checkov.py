"""Tests for v6.87.0 CheckovAnalyzer integration."""

from pathlib import Path

from devai import CheckovAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """\
framework:
  - terraform
  - kubernetes
  - dockerfile
soft-fail: false
download-external-modules: false
skip-check: []
skip-path:
  - .terraform/
  - node_modules/
"""

UNSAFE_CONFIG = """\
framework: []
soft-fail: true
download-external-modules: true
BC_API_KEY: bridgecrew_secret_token_12345
api_key: supersecret123
skip-check:
  - '*'
  - CKV_AWS_*
  - CKV_GCP_*
skip-path:
  - "**"
  - /
var-file: secrets.tfvars
evaluate-variables: true
skip-suppression: true
# checkov -d . --soft-fail --skip-check *
"""


class TestCheckovAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        (tmp_path / ".checkov.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = CheckovAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.stats.findings == 0

    def test_detects_unsafe_config_patterns(self, tmp_path: Path):
        (tmp_path / "checkov.yaml").write_text(UNSAFE_CONFIG, encoding="utf-8")
        analyzer = CheckovAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "hardcoded_secret" in kinds
        assert "api_key" in kinds
        assert "soft_fail" in kinds
        assert "wildcard_skip_check" in kinds
        assert "broad_skip_check" in kinds
        assert "broad_skip_path" in kinds
        assert "empty_framework" in kinds
        assert "download_external_modules" in kinds
        assert "secrets_var_file" in kinds
        assert "evaluate_variables" in kinds
        assert "skip_suppression" in kinds
        assert "cli_wildcard_skip" in kinds

    def test_facade_checkov(self):
        analyzer = DevAI.mock().checkov(".")
        assert isinstance(analyzer, CheckovAnalyzer)

    def test_project_health_includes_checkov_category(self, tmp_path: Path):
        (tmp_path / ".checkov.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "checkov" in names

    def test_generate_hardened_template(self):
        template = CheckovAnalyzer(".").generate_hardened_template()
        assert "framework:" in template
        assert "soft-fail: false" in template

    def test_checkov_baseline_file(self, tmp_path: Path):
        (tmp_path / ".checkov.baseline").write_text('{"check_type": "terraform"}\n', encoding="utf-8")
        analyzer = CheckovAnalyzer(str(tmp_path))
        assert len(analyzer.files()) == 1
        kinds = {f.kind for f in analyzer.analyze()}
        assert "baseline_present" in kinds

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".checkov.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = CheckovAnalyzer(str(tmp_path)).to_context()
        assert "Checkov config analysis" in context
        assert "health score" in context
