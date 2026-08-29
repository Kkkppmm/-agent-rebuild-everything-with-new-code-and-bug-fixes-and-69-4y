"""Tests for BlackAnalyzer."""

from pathlib import Path

from devai.black_analyzer import BlackAnalyzer, BlackFinding


INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.black]
line-length = 300
preview = true
fast = true
skip-string-normalization = true
exclude = ["src", "lib"]
target-version = ["py27", "py36"]
unstable = ["string_processing"]
api_key = api_key=hardcoded_secret_value_12345

[tool.pytest.ini_options]
addopts = "-q"
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.black]
line-length = 88
target-version = ["py310"]
preview = false
skip-string-normalization = false
extend-exclude = '''
/(
  \\.git
  | \\.venv
)/
'''
"""


class TestBlackAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = BlackAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "skip_string_normalization" in kinds
        assert "preview" in kinds
        assert "fast" in kinds
        assert "line_length_high" in kinds
        assert "exclude_source" in kinds
        assert "target_version_old" in kinds
        assert "unstable_features" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = BlackAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].line_length == 88
        assert analyzer.infos[0].target_versions == ["py310"]

    def test_pyproject_ignores_non_black_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = BlackAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 14 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = BlackAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = BlackFinding(
            kind="preview",
            severity="medium",
            message="test message",
            path="pyproject.toml",
            lineno=5,
            line="preview = true",
        )
        assert "pyproject.toml:5" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = BlackAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.black]" in template
        assert "line-length = 88" in template
        assert "skip-string-normalization = false" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[tool.black]\npreview = true\n",
            encoding="utf-8",
        )
        analyzer = BlackAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Black analysis:" in context
        assert "preview" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "pyproject.toml").write_text(
            "[tool.black]\nskip-string-normalization = true\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        black = next(c for c in report.categories if c.name == "black")
        assert black.score < 100.0
        assert black.details.get("findings", 0) > 0
