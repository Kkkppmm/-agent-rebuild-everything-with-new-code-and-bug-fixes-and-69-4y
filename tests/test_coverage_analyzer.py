"""Tests for CoverageAnalyzer."""

from pathlib import Path

from devai.coverage_analyzer import CoverageAnalyzer, CoverageFinding


INSECURE_COVERAGERC = """\
[run]
branch = false
relative_files = false
omit = src, lib, app
data_file = /tmp/coverage.dat
plugins = ../untrusted/plugin.py
api_key = api_key=hardcoded_secret_value_12345

[report]
fail_under = 0
show_missing = false
skip_covered = true
precision = 0
exclude_lines =
    pragma: no cover
    def __repr__
    raise NotImplementedError
    pass
disable_warnings = *

[html]
directory = htmlcov
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.coverage.run]
source = ["src"]
branch = true
relative_files = true
omit = ["*/tests/*"]

[tool.coverage.report]
fail_under = 80
show_missing = true
skip_covered = false
precision = 1
"""

INSECURE_SETUP_CFG = """\
[metadata]
name = demo

[coverage:run]
omit = src

[coverage:report]
fail_under = 25
"""

INSECURE_PYPROJECT = """\
[tool.coverage.run]
omit = app

[tool.pytest.ini_options]
addopts = "-q"
"""


class TestCoverageAnalyzer:
    def test_detects_insecure_coveragerc(self, tmp_path: Path):
        (tmp_path / ".coveragerc").write_text(INSECURE_COVERAGERC, encoding="utf-8")
        analyzer = CoverageAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "fail_under_zero" in kinds
        assert "omit_source" in kinds
        assert "skip_covered" in kinds
        assert "show_missing_false" in kinds
        assert "insecure_data_file" in kinds
        assert "plugin_untrusted" in kinds
        assert "exclude_lines_broad" in kinds
        assert "branch_disabled" in kinds
        assert "relative_files_false" in kinds
        assert "precision_zero" in kinds
        assert "disable_warnings" in kinds
        assert "source_omitted" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = CoverageAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].fail_under == 80
        assert analyzer.infos[0].branch is True

    def test_setup_cfg_coverage_section(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(INSECURE_SETUP_CFG, encoding="utf-8")
        analyzer = CoverageAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "omit_source" in kinds
        assert "fail_under_low" in kinds
        assert all("setup.cfg" in f.path for f in findings)

    def test_pyproject_ignores_non_coverage_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CoverageAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "omit_source" in kinds
        assert all(f.lineno <= 3 for f in findings if f.kind != "source_omitted")

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = CoverageAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = CoverageFinding(
            kind="fail_under_zero",
            severity="high",
            message="test message",
            path=".coveragerc",
            lineno=3,
            line="fail_under = 0",
        )
        assert ".coveragerc:3" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = CoverageAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.coverage.run]" in template
        assert "fail_under = 80" in template
        assert "branch = true" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".coveragerc").write_text("fail_under = 0\n", encoding="utf-8")
        analyzer = CoverageAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Coverage analysis:" in context
        assert "fail_under=0" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".coveragerc").write_text("fail_under = 0\n", encoding="utf-8")
        health = ProjectHealth(str(tmp_path), scan_secrets=False)
        report = health.analyze()
        coverage_cat = next(c for c in report.categories if c.name == "coverage")
        assert coverage_cat.score < 100.0
