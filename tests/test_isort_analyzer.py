"""Tests for IsortAnalyzer."""

from pathlib import Path

from devai.isort_analyzer import IsortAnalyzer, IsortFinding


INSECURE_ISORT_CFG = """\
[settings]
profile = black
line_length = 79
honor_noqa = false
skip = src, lib
force_sort_within_sections = false
combine_as_imports = false
known_third_party = []
api_key = api_key=hardcoded_secret_value_12345
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.isort]
profile = "black"
line_length = 88
honor_noqa = true
force_sort_within_sections = true
combine_as_imports = true
known_third_party = ["httpx", "pydantic"]
"""

INSECURE_PYPROJECT = """\
[tool.isort]
profile = black
line_length = 72
honor_noqa = false

[tool.pytest.ini_options]
addopts = "-q"
"""


class TestIsortAnalyzer:
    def test_detects_insecure_isort_cfg(self, tmp_path: Path):
        (tmp_path / ".isort.cfg").write_text(INSECURE_ISORT_CFG, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "honor_noqa_false" in kinds
        assert "skip_source" in kinds
        assert "black_profile_conflict" in kinds
        assert "force_sort_within_sections_false" in kinds
        assert "combine_as_imports_false" in kinds
        assert "known_third_party_empty" in kinds
        assert analyzer.health_score() <= 50.0

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
        kinds = {f.kind for f in findings}
        assert "honor_noqa_false" in kinds
        assert "black_profile_conflict" in kinds
        assert all(f.lineno <= 4 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = IsortAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = IsortFinding(
            kind="honor_noqa_false",
            severity="medium",
            message="test message",
            path=".isort.cfg",
            lineno=3,
            line="honor_noqa = false",
        )
        assert "[medium]" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = IsortAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert 'profile = "black"' in template
        assert "honor_noqa = true" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".isort.cfg").write_text(INSECURE_ISORT_CFG, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Isort analysis:" in context
        assert "profile=black" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / ".isort.cfg").write_text(INSECURE_ISORT_CFG, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Isort configs: 1 file(s)" in summary
