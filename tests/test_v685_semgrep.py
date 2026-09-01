"""Tests for v6.85.0 SemgrepAnalyzer integration."""

from pathlib import Path

from devai import DevAI, SemgrepAnalyzer
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """\
rules:
  - id: no-eval
    pattern: eval(...)
    message: Avoid eval()
    languages: [python]
    severity: ERROR
    metadata:
      category: security
paths:
  exclude:
    - tests/fixtures/
"""

UNSAFE_CONFIG = """\
rules: []
status: disable
app_token: sgp_abcdefghijklmnopqrstuvwxyz1234567890
api_key: supersecret123
url: http://semgrep.example.com/api
paths:
  exclude:
    - "**"
    - /*
pattern: $X
pattern-not: ...
severity: INFO
validate: false
nosemgrep: true
autofix: true
confidence: LOW
scan_args: --dangerous --allow-untrusted-autofix
"""


class TestSemgrepAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        (tmp_path / ".semgrep.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = SemgrepAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.configs == 1
        assert analyzer.stats.findings == 0

    def test_detects_unsafe_config_patterns(self, tmp_path: Path):
        (tmp_path / ".semgrep.yml").write_text(UNSAFE_CONFIG, encoding="utf-8")
        analyzer = SemgrepAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "hardcoded_secret" in kinds
        assert "app_token" in kinds
        assert "insecure_http" in kinds
        assert "broad_exclude" in kinds
        assert "disabled_rule" in kinds
        assert "catch_all_pattern" in kinds
        assert "severity_downgrade" in kinds
        assert "skip_validation" in kinds
        assert "unsafe_autofix" in kinds
        assert "empty_rules" in kinds
        assert "wildcard_pattern_not" in kinds
        assert "low_confidence" in kinds
        assert "dangerous_flag" in kinds

    def test_facade_semgrep(self):
        analyzer = DevAI.mock().semgrep(".")
        assert isinstance(analyzer, SemgrepAnalyzer)

    def test_project_health_includes_semgrep_category(self, tmp_path: Path):
        (tmp_path / ".semgrep.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "semgrep" in names

    def test_generate_hardened_template(self):
        template = SemgrepAnalyzer(".").generate_hardened_template()
        assert "severity: ERROR" in template
        assert "SEMGREP_APP_TOKEN" in template

    def test_semgrep_config_in_subdirectory(self, tmp_path: Path):
        semgrep_dir = tmp_path / ".semgrep"
        semgrep_dir.mkdir()
        (semgrep_dir / "settings.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = SemgrepAnalyzer(str(tmp_path))
        assert len(analyzer.files()) == 1
        assert analyzer.stats.configs == 1

    def test_rule_file_detection(self, tmp_path: Path):
        rules_dir = tmp_path / ".semgrep" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "custom.yml").write_text(
            'rules:\n  - id: test\n    pattern: eval(...)\n    severity: ERROR\n',
            encoding="utf-8",
        )
        analyzer = SemgrepAnalyzer(str(tmp_path))
        assert len(analyzer.files()) == 1
        assert analyzer.infos[0].rule_count == 1

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".semgrep.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = SemgrepAnalyzer(str(tmp_path)).to_context()
        assert "Semgrep config analysis" in context
        assert "health score" in context
