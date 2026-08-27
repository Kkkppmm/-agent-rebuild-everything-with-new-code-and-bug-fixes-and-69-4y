"""Tests for PyrightAnalyzer."""

from pathlib import Path

from devai.pyright_analyzer import PyrightAnalyzer, PyrightFinding


INSECURE_PYRIGHT = """\
{
  "typeCheckingMode": "off",
  "reportMissingImports": false,
  "reportGeneralTypeIssues": false,
  "strict": false,
  "extraPaths": ["/tmp/stubs"],
  "api_key": "hardcoded_secret_value_12345"
}
"""

HARDENED_PYRIGHT = """\
{
  "typeCheckingMode": "standard",
  "pythonVersion": "3.10",
  "reportMissingImports": true,
  "reportGeneralTypeIssues": true
}
"""


class TestPyrightAnalyzer:
    def test_detects_insecure_pyright(self, tmp_path: Path):
        (tmp_path / "pyrightconfig.json").write_text(INSECURE_PYRIGHT, encoding="utf-8")
        analyzer = PyrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "type_checking_off" in kinds
        assert "report_missing_imports_false" in kinds
        assert "report_general_type_issues_false" in kinds
        assert "insecure_paths" in kinds
        assert "strict_false" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyright_scores_well(self, tmp_path: Path):
        (tmp_path / "pyrightconfig.json").write_text(HARDENED_PYRIGHT, encoding="utf-8")
        analyzer = PyrightAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].type_checking_mode is None

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = PyrightAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = PyrightFinding(
            kind="type_checking_off",
            severity="high",
            message="test message",
            path="pyrightconfig.json",
            lineno=2,
            line='"typeCheckingMode": "off"',
        )
        assert "pyrightconfig.json:2" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = PyrightAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "typeCheckingMode" in template
        assert "reportMissingImports" in template

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "pyrightconfig.json").write_text(
            '{"typeCheckingMode": "off"}\n',
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        pyright = next(c for c in report.categories if c.name == "pyright")
        assert pyright.score < 100.0
        assert pyright.details.get("findings", 0) > 0
