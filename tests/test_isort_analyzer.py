"""Tests for IsortAnalyzer."""

from pathlib import Path

from devai.isort_analyzer import IsortAnalyzer, IsortFinding


INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.isort]
profile = "black"
line_length = 120
multi_line_output = 5
honor_noqa = false
force_single_line = true
force_sort_within_sections = false
skip = ["src", "lib"]
skip_glob = ["**/*"]
skip_gitignore = true
filter_files = true
known_first_party = []
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
multi_line_output = 3
honor_noqa = true
known_first_party = ["demo"]
skip_gitignore = false
"""

INSECURE_SETUP_CFG = """\
[isort]
profile = django
honor_noqa = false
skip = tests
"""

HARDENED_ISORT_CFG = """\
[settings]
profile = black
line_length = 88
multi_line_output = 3
honor_noqa = true
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
        assert "black_line_length_mismatch" in kinds
        assert "black_multi_line_output_mismatch" in kinds
        assert "force_single_line" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].profile == "black"
        assert analyzer.infos[0].line_length == 88

    def test_setup_cfg_isort_section(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(INSECURE_SETUP_CFG, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "honor_noqa_false" in kinds
        assert "profile_not_black" in kinds

    def test_isort_cfg_file(self, tmp_path: Path):
        (tmp_path / ".isort.cfg").write_text(HARDENED_ISORT_CFG, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.stats.config_files == 1

    def test_pyproject_ignores_non_isort_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 18 for f in findings)

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
            line="honor_noqa = false",
        )
        assert "[high]" in finding.format()
        assert "pyproject.toml:5" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = IsortAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "profile = \"black\"" in template
        assert "honor_noqa = true" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Isort analysis:" in context
        assert "health score:" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        assert "1 file(s)" in analyzer.summary()
