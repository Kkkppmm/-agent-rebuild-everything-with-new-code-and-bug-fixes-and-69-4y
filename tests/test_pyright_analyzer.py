"""Tests for PyrightAnalyzer."""

from pathlib import Path

from devai.pyright_analyzer import PyrightAnalyzer, PyrightFinding


INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.pyright]
typeCheckingMode = "off"
reportMissingImports = false
reportUnknownMemberType = false
reportGeneralTypeIssues = false
reportMissingTypeStubs = false
reportOptionalMemberAccess = false
reportPrivateUsage = false
strictParameterNoneValueChecking = false
useLibraryCodeForTypes = false
exclude = ["src", "lib", "app"]
extraPaths = ["/tmp/stubs", "../external"]
stubPath = "/etc/pyright-stubs"
api_key = "api_key=hardcoded_secret_value_12345"

[tool.pytest.ini_options]
addopts = "-q"
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.pyright]
pythonVersion = "3.10"
typeCheckingMode = "standard"
reportMissingImports = true
reportUnknownMemberType = true
reportGeneralTypeIssues = true
exclude = [
    "**/node_modules",
    "**/__pycache__",
    ".venv",
]
"""

INSECURE_JSON = """\
{
  "typeCheckingMode": "basic",
  "reportMissingImports": false,
  "reportGeneralTypeIssues": false,
  "exclude": ["src", "lib"],
  "extraPaths": ["/tmp/stubs"]
}
"""


class TestPyrightAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PyrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "type_checking_relaxed" in kinds
        assert "report_missing_imports_false" in kinds
        assert "report_general_type_false" in kinds
        assert "exclude_source" in kinds
        assert "insecure_extra_paths" in kinds
        assert "insecure_stub_path" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = PyrightAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].type_checking_mode == "standard"

    def test_json_config_detects_issues(self, tmp_path: Path):
        (tmp_path / "pyrightconfig.json").write_text(INSECURE_JSON, encoding="utf-8")
        analyzer = PyrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "type_checking_relaxed" in kinds
        assert "report_missing_imports_false" in kinds
        assert "report_general_type_false" in kinds
        assert "exclude_source" in kinds
        assert "insecure_extra_paths" in kinds

    def test_pyproject_ignores_non_pyright_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PyrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 17 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = PyrightAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = PyrightFinding(
            kind="type_checking_relaxed",
            severity="high",
            message="test message",
            path="pyrightconfig.json",
            lineno=3,
            line='"typeCheckingMode": "off"',
        )
        assert "pyrightconfig.json:3" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = PyrightAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.pyright]" in template
        assert 'typeCheckingMode = "standard"' in template
        assert "reportMissingImports = true" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "pyrightconfig.json").write_text(INSECURE_JSON, encoding="utf-8")
        analyzer = PyrightAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Pyright analysis:" in context
        assert "typeCheckingMode" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "pyrightconfig.json").write_text(INSECURE_JSON, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        pyright = next(c for c in report.categories if c.name == "pyright")
        assert pyright.score < 100.0
        assert pyright.details.get("findings", 0) > 0
