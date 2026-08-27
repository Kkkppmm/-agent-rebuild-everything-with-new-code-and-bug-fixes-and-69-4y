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
skip_gitignore = false
force_single_line = true
skip = ["src", "lib"]
multi_line_output = 3
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
skip_gitignore = true
known_first_party = ["demo"]
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
        assert "black_profile_conflict" in kinds
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
        (tmp_path / "setup.cfg").write_text(
            "[metadata]\nname = demo\n\n[isort]\nhonor_noqa = false\n",
            encoding="utf-8",
        )
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "honor_noqa_false" for f in findings)

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
