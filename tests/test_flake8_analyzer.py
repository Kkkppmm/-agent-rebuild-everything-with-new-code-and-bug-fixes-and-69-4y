"""Tests for Flake8Analyzer."""

from pathlib import Path

from devai.flake8_analyzer import Flake8Analyzer, Flake8Finding


INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.flake8]
max-line-length = 300
max-complexity = 50
ignore = E, W, F
extend-ignore = S101, S105
exclude = src, lib, .venv
per-file-ignores =
    settings.py: S105
api_key = api_key=hardcoded_secret_value_12345

[tool.pytest.ini_options]
addopts = "-q"
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.flake8]
max-line-length = 88
max-complexity = 10
extend-ignore = E203, W503
exclude =
    .git,
    __pycache__,
    .venv,
    build,
    dist
"""

INSECURE_FLAKE8 = """\
[flake8]
max-line-length = 40
ignore = ALL
exclude = app/**
ban-relative-imports = false
count = true
statistics = true
select =
"""


class TestFlake8Analyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = Flake8Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "ignore_broad" in kinds
        assert "disabled_security_rule" in kinds
        assert "exclude_source" in kinds
        assert "max_line_length_high" in kinds
        assert "max_complexity_high" in kinds
        assert "per_file_security_ignore" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = Flake8Analyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].max_line_length == 88
        assert analyzer.infos[0].max_complexity == 10

    def test_flake8_file_detects_issues(self, tmp_path: Path):
        (tmp_path / ".flake8").write_text(INSECURE_FLAKE8, encoding="utf-8")
        analyzer = Flake8Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "ignore_all" in kinds
        assert "max_line_length_low" in kinds
        assert "ban_relative_imports_false" in kinds
        assert "count_enabled" in kinds
        assert "statistics_enabled" in kinds
        assert "empty_select" in kinds

    def test_pyproject_ignores_non_flake8_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = Flake8Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 14 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = Flake8Analyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = Flake8Finding(
            kind="ignore_all",
            severity="high",
            message="test message",
            path=".flake8",
            lineno=3,
            line="ignore = ALL",
        )
        assert ".flake8:3" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = Flake8Analyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[flake8]" in template
        assert "max-line-length = 88" in template
        assert "max-complexity = 10" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".flake8").write_text(
            "[flake8]\nignore = ALL\n",
            encoding="utf-8",
        )
        analyzer = Flake8Analyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "flake8 analysis:" in context
        assert "ignore" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".flake8").write_text(
            "[flake8]\nignore = ALL\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        flake8 = next(c for c in report.categories if c.name == "flake8")
        assert flake8.score < 100.0
        assert flake8.details.get("findings", 0) > 0
