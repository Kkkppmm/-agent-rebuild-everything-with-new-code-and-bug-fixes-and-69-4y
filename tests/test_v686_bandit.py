"""Tests for v6.86.0 BanditAnalyzer integration."""

from pathlib import Path

from devai import BanditAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """\
exclude_dirs:
  - /tests/fixtures/
  - /.venv/
skips: []
assert_used:
  skips:
    - '**/test_*.py'
    - '**/tests/**'
"""

UNSAFE_CONFIG = """\
exclude_dirs:
  - "**"
  - /
skips:
  - '*'
  - B601
  - B608
  - B105
  - B307
  - B301
  - B101
tests: []
api_key: supersecret123
BANDIT_API_KEY: bandit_secret_token_12345
assert_used:
  skips: []
baseline: true
ignore-nosec: true
nosec: true
confidence: LOW
"""


class TestBanditAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        (tmp_path / "bandit.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = BanditAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.stats.findings == 0

    def test_detects_unsafe_config_patterns(self, tmp_path: Path):
        (tmp_path / "bandit.yaml").write_text(UNSAFE_CONFIG, encoding="utf-8")
        analyzer = BanditAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "hardcoded_secret" in kinds
        assert "api_key" in kinds
        assert "broad_exclude" in kinds
        assert "wildcard_skip" in kinds
        assert "shell_injection_skip" in kinds
        assert "sql_injection_skip" in kinds
        assert "hardcoded_password_skip" in kinds
        assert "eval_skip" in kinds
        assert "pickle_skip" in kinds
        assert "security_test_skip" in kinds
        assert "disabled_assert_check" in kinds
        assert "baseline_bypass" in kinds
        assert "nosec_bypass" in kinds
        assert "low_confidence" in kinds
        assert "empty_tests" in kinds

    def test_facade_bandit(self):
        analyzer = DevAI.mock().bandit(".")
        assert isinstance(analyzer, BanditAnalyzer)

    def test_project_health_includes_bandit_category(self, tmp_path: Path):
        (tmp_path / "bandit.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "bandit" in names

    def test_generate_hardened_template(self):
        template = BanditAnalyzer(".").generate_hardened_template()
        assert "exclude_dirs" in template
        assert "skips: []" in template

    def test_bandit_dotfile_config(self, tmp_path: Path):
        (tmp_path / ".bandit").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = BanditAnalyzer(str(tmp_path))
        assert len(analyzer.files()) == 1

    def test_pyproject_bandit_section(self, tmp_path: Path):
        pyproject = f"""\
[tool.bandit]
{HARDENED_CONFIG}
"""
        (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        analyzer = BanditAnalyzer(str(tmp_path))
        assert len(analyzer.files()) == 1
        assert analyzer.stats.findings == 0

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "bandit.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = BanditAnalyzer(str(tmp_path)).to_context()
        assert "Bandit config analysis" in context
        assert "health score" in context
