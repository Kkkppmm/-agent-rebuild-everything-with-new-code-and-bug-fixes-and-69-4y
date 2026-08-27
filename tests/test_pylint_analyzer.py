"""Tests for PylintAnalyzer."""

from pathlib import Path

from devai.pylint_analyzer import PylintAnalyzer, PylintFinding


INSECURE_PYLINTRC = """\
[MASTER]
init-hook = exec('import os')
disable = ALL, exec-used, subprocess-run-check
fail-under = 2.0
load-plugins = pylint_django
api_key = hardcoded_secret_value_12345
"""

HARDENED_PYLINTRC = """\
[MASTER]
fail-under = 8.0

[MESSAGES CONTROL]
disable =
"""


class TestPylintAnalyzer:
    def test_detects_insecure_pylintrc(self, tmp_path: Path):
        (tmp_path / ".pylintrc").write_text(INSECURE_PYLINTRC, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "disable_all" in kinds
        assert "unsafe_init_hook" in kinds
        assert "disabled_security_rules" in kinds
        assert "fail_under_low" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pylintrc_scores_well(self, tmp_path: Path):
        (tmp_path / ".pylintrc").write_text(HARDENED_PYLINTRC, encoding="utf-8")
        analyzer = PylintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].fail_under == 8.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = PylintAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = PylintFinding(
            kind="disable_all",
            severity="high",
            message="test message",
            path=".pylintrc",
            lineno=3,
            line="disable = ALL",
        )
        assert ".pylintrc:3" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = PylintAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.pylint.main]" in template
        assert "fail-under = 8.0" in template

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".pylintrc").write_text(
            "[MASTER]\ndisable = ALL\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        pylint = next(c for c in report.categories if c.name == "pylint")
        assert pylint.score < 100.0
        assert pylint.details.get("findings", 0) > 0
