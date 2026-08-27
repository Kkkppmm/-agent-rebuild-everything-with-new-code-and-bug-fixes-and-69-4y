"""Tests for IsortAnalyzer."""

from pathlib import Path

from devai.isort_analyzer import IsortAnalyzer, IsortFinding


INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.isort]
profile = "black"
line_length = 120
honor_noqa = false
filter_files = false
no_sections = true
force_single_line = true
skip = ["src", "lib"]
skip_glob = ["**/*", "src/*"]
known_third_party = ["*"]
api_key = api_key=hardcoded_secret_value_12345

[tool.pytest.ini_options]
addopts = "-q"
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.isort]
profile = "black"
line_length = 88
honor_noqa = true
filter_files = true
combine_as_imports = true
force_sort_within_sections = true
"""

INSECURE_ISORT_CFG = """\
[settings]
profile = black
line_length = 200
honor_noqa = false
skip_glob = src/*
"""

INSECURE_SETUP_CFG = """\
[metadata]
name = demo

[isort]
honor_noqa = false
skip = app
"""


class TestIsortAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "honor_noqa_false" in kinds
        assert "skip_source" in kinds
        assert "skip_glob_broad" in kinds
        assert "skip_glob_source" in kinds
        assert "no_sections" in kinds
        assert "filter_files_false" in kinds
        assert "black_profile_conflict" in kinds
        assert "known_wildcard" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].profile == "black"
        assert analyzer.infos[0].line_length == 88

    def test_pyproject_ignores_non_isort_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 16 for f in findings)

    def test_isort_cfg_detected(self, tmp_path: Path):
        (tmp_path / ".isort.cfg").write_text(INSECURE_ISORT_CFG, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "honor_noqa_false" in kinds
        assert "line_length_high" in kinds
        assert analyzer.stats.config_files == 1

    def test_setup_cfg_detected(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(INSECURE_SETUP_CFG, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "honor_noqa_false" in kinds
        assert "skip_source" in kinds

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = IsortAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = IsortFinding(
            kind="honor_noqa_false",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=5,
        )
        assert "[high]" in finding.format()
        assert "pyproject.toml:5" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = IsortAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.isort]" in template
        assert "honor_noqa = true" in template
        assert 'profile = "black"' in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[tool.isort]\nhonor_noqa = false\n",
            encoding="utf-8",
        )
        analyzer = IsortAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Isort analysis:" in context
        assert "honor_noqa" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "pyproject.toml").write_text(
            "[tool.isort]\nhonor_noqa = false\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        isort = next(c for c in report.categories if c.name == "isort")
        assert isort.score < 100.0
        assert isort.details.get("findings", 0) > 0

    def test_facade_integration(self, tmp_path: Path):
        from devai import DevAI

        (tmp_path / "pyproject.toml").write_text(
            "[tool.isort]\nhonor_noqa = false\n",
            encoding="utf-8",
        )
        ai = DevAI.mock()
        analyzer = ai.isort(str(tmp_path))
        assert analyzer.health_score() < 100.0
