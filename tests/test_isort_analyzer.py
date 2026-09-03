"""Tests for IsortAnalyzer."""

from pathlib import Path

from devai.isort_analyzer import IsortAnalyzer, IsortFinding


INSECURE_PYPROJECT = """\
[project]
name = "demo"

[tool.isort]
line_length = 300
force_single_line = true
honor_noqa = false
skip_gitignore = true
skip = ["src", "lib"]
src_paths = ["tests", "docs"]
sections = ["THIRDPARTY", "FIRSTPARTY"]
profile = "google"
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
combine_as_imports = true
include_trailing_comma = true
use_parentheses = true
honor_noqa = true
atomic = true
skip_gitignore = false
known_first_party = ["demo"]
src_paths = ["src", "tests"]
"""

INSECURE_ISORT_CFG = """\
[isort]
line_length = 40
float_to_top = true
atomic = false
combine_as_imports = false
include_trailing_comma = false
use_parentheses = false
extend_skip_glob = ["app/**"]
"""


class TestIsortAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "honor_noqa_false" in kinds
        assert "force_single_line" in kinds
        assert "skip_source" in kinds
        assert "skip_gitignore_true" in kinds
        assert "line_length_high" in kinds
        assert "sections_missing_core" in kinds
        assert "non_black_profile" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].line_length == 88
        assert analyzer.infos[0].profile == "black"

    def test_isort_cfg_detects_issues(self, tmp_path: Path):
        (tmp_path / ".isort.cfg").write_text(INSECURE_ISORT_CFG, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "line_length_low" in kinds
        assert "float_to_top" in kinds
        assert "atomic_false" in kinds
        assert "combine_as_imports_false" in kinds
        assert "skip_source" in kinds

    def test_pyproject_ignores_non_isort_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 15 for f in findings)

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
        assert "pyproject.toml:5" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = IsortAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.isort]" in template
        assert 'profile = "black"' in template
        assert "honor_noqa = true" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[tool.isort]\nhonor_noqa = false\n",
            encoding="utf-8",
        )
        analyzer = IsortAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "isort analysis:" in context
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
