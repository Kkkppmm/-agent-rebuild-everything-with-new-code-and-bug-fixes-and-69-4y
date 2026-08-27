"""Tests for PyrightAnalyzer."""

from pathlib import Path

from devai.pyright_analyzer import PyrightAnalyzer, PyrightFinding


INSECURE_PYRIGHT_JSON = """\
{
  "typeCheckingMode": "off",
  "reportMissingImports": false,
  "reportOptionalMemberAccess": false,
  "reportGeneralTypeIssues": false,
  "reportPrivateUsage": false,
  "useLibraryCodeForTypes": false,
  "exclude": ["src", "lib"],
  "extraPaths": ["/tmp/untrusted"],
  "venvPath": "/tmp/venv",
  "api_key": "api_key=hardcoded_secret_value_12345"
}
"""

HARDENED_PYRIGHT_JSON = """\
{
  "typeCheckingMode": "standard",
  "reportMissingImports": true,
  "reportOptionalMemberAccess": true,
  "reportGeneralTypeIssues": true,
  "useLibraryCodeForTypes": true,
  "exclude": ["**/node_modules", ".venv"]
}
"""

INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.pyright]
typeCheckingMode = "basic"
reportMissingImports = false
exclude = ["src"]

[tool.pytest.ini_options]
addopts = "-q"
"""


class TestPyrightAnalyzer:
    def test_detects_insecure_pyright_json(self, tmp_path: Path):
        (tmp_path / "pyrightconfig.json").write_text(INSECURE_PYRIGHT_JSON, encoding="utf-8")
        analyzer = PyrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "type_checking_relaxed" in kinds
        assert "report_missing_imports_false" in kinds
        assert "report_optional_false" in kinds
        assert "exclude_source" in kinds
        assert "insecure_extra_paths" in kinds
        assert "insecure_venv_path" in kinds
        assert "report_general_false" in kinds
        assert "report_private_false" in kinds
        assert "use_library_code_false" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyright_json_scores_well(self, tmp_path: Path):
        (tmp_path / "pyrightconfig.json").write_text(HARDENED_PYRIGHT_JSON, encoding="utf-8")
        analyzer = PyrightAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].type_checking_mode == "standard"

    def test_pyproject_ignores_non_pyright_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PyrightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 10 for f in findings)

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
            lineno=2,
            line='"typeCheckingMode": "off"',
        )
        assert "pyrightconfig.json:2" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = PyrightAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "typeCheckingMode" in template
        assert "standard" in template
        assert "reportMissingImports" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "pyrightconfig.json").write_text(
            '{"typeCheckingMode": "off"}\n',
            encoding="utf-8",
        )
        analyzer = PyrightAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Pyright analysis:" in context
        assert "off" in context

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
