"""Tests for PyreflyAnalyzer."""

from pathlib import Path

from devai.pyrefly_analyzer import PyreflyAnalyzer, PyreflyFinding


INSECURE_PYREFLY_TOML = """\
preset = "off"
project-excludes = ["src", "lib"]
replace-imports-with-any = ["**", "*.series"]
disable-type-errors-in-ide = true
permissive-ignores = true
ignore-errors-in-generated-code = true
search-path = ["/tmp/untrusted"]

[errors]
bad-assignment = false
invalid-argument = false
missing-import = false
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.pyrefly]
preset = "strict"
project-includes = ["src"]
project-excludes = ["**/__pycache__", ".venv"]
search-path = ["src"]
"""

INSECURE_PYPROJECT = """\
[tool.pyrefly]
preset = "legacy"
project-excludes = ["src"]
replace-imports-with-any = ["sympy.*"]

[tool.pyrefly.errors]
bad-return = false

[tool.pytest.ini_options]
addopts = "-q"
"""


class TestPyreflyAnalyzer:
    def test_detects_insecure_pyrefly_toml(self, tmp_path: Path):
        (tmp_path / "pyrefly.toml").write_text(INSECURE_PYREFLY_TOML, encoding="utf-8")
        analyzer = PyreflyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "preset_off" in kinds
        assert "critical_error_disabled" in kinds
        assert "replace_imports_with_any" in kinds
        assert "exclude_source" in kinds
        assert "insecure_path" in kinds
        assert "disable_type_errors_ide" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = PyreflyAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_pyproject_ignores_non_pyrefly_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PyreflyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 8 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = PyreflyAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_pyrefly_toml_and_pyproject_both_scanned(self, tmp_path: Path):
        (tmp_path / "pyrefly.toml").write_text('preset = "off"\n', encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[tool.pyrefly]\npreset = "strict"\n',
            encoding="utf-8",
        )
        analyzer = PyreflyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 2
        assert any(f.kind == "preset_off" for f in findings)

    def test_generate_hardened_template(self):
        template = PyreflyAnalyzer(".").generate_hardened_template()
        assert "[tool.pyrefly]" in template
        assert 'preset = "strict"' in template

    def test_finding_format(self):
        finding = PyreflyFinding(
            kind="preset_off",
            severity="high",
            message="test message",
            path="pyrefly.toml",
            lineno=2,
        )
        assert "high" in finding.format()
        assert "pyrefly.toml:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pyrefly.toml").write_text('preset = "off"\n', encoding="utf-8")
        analyzer = PyreflyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Pyrefly analysis:" in context
        assert "preset" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / "pyrefly.toml").write_text('preset = "off"\n', encoding="utf-8")
        analyzer = PyreflyAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Pyrefly configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "pyrefly.toml").write_text(
            'preset = "off"\nreplace-imports-with-any = ["**"]\n',
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        pyrefly = next(c for c in report.categories if c.name == "pyrefly")
        assert pyrefly.score < 100.0
        assert pyrefly.details.get("findings", 0) > 0
