"""Tests for BasedpyrightAnalyzer."""

from pathlib import Path

from devai.basedpyright_analyzer import BasedpyrightAnalyzer, BasedpyrightFinding


INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.basedpyright]
typeCheckingMode = "off"
reportMissingImports = false
reportGeneralTypeIssues = false
reportUnknownMemberType = false
reportUnknownArgumentType = false
reportUnknownVariableType = false
reportUntypedFunctionDecorator = false
reportUntypedClassDecorator = false
reportUntypedBaseClass = false
analyzeUnannotatedFunctions = false
strictListInference = false
strictDictionaryInference = false
reportMissingTypeStubs = false
reportAny = false
reportExplicitAny = false
reportUnusedCallResult = false
reportImplicitOverride = false
reportPrivateImportUsage = false
reportDeprecated = false
reportIncompatibleMethodOverride = false
reportIncompatibleVariableOverride = false
reportOverlappingOverload = false
exclude = ["src", "lib"]
extraPaths = ["/tmp/untrusted"]
baselineFile = "/tmp/baseline.json"
api_key = "api_key=hardcoded_secret_value_12345"

[tool.pytest.ini_options]
addopts = "-q"
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.basedpyright]
include = ["src"]
exclude = ["**/__pycache__", ".venv"]
typeCheckingMode = "strict"
reportMissingImports = true
reportGeneralTypeIssues = true
reportAny = true
reportExplicitAny = true
reportImplicitOverride = true
"""


class TestBasedpyrightAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = BasedpyrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "type_checking_off" in kinds
        assert "report_missing_imports_false" in kinds
        assert "report_general_type_issues_false" in kinds
        assert "report_any_false" in kinds
        assert "report_explicit_any_false" in kinds
        assert "report_implicit_override_false" in kinds
        assert "exclude_source" in kinds
        assert "insecure_extra_path" in kinds
        assert "baseline_file_insecure" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = BasedpyrightAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].type_checking_mode == "strict"

    def test_ignores_non_basedpyright_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = BasedpyrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 36 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = BasedpyrightAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_ignores_pyright_only_config(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[tool.pyright]\ntypeCheckingMode = "off"\n',
            encoding="utf-8",
        )
        analyzer = BasedpyrightAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = BasedpyrightFinding(
            kind="type_checking_off",
            severity="high",
            message="typeCheckingMode=off disables Basedpyright",
            path="pyproject.toml",
            lineno=5,
            line='typeCheckingMode = "off"',
        )
        assert "pyproject.toml:5" in finding.format()

    def test_generate_template(self):
        analyzer = BasedpyrightAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.basedpyright]" in template
        assert "reportAny" in template
        assert "reportImplicitOverride" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[tool.basedpyright]\ntypeCheckingMode = "off"\n',
            encoding="utf-8",
        )
        analyzer = BasedpyrightAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Basedpyright analysis:" in context
        assert "type_checking_off" in context or "off" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "pyproject.toml").write_text(
            '[tool.basedpyright]\ntypeCheckingMode = "off"\nreportGeneralTypeIssues = false\n',
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        basedpyright = next(c for c in report.categories if c.name == "basedpyright")
        assert basedpyright.score < 100.0
        assert basedpyright.details.get("findings", 0) > 0
