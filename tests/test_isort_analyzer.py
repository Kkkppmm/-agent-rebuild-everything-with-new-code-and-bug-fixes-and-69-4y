"""Tests for IsortAnalyzer."""

from pathlib import Path

from devai.isort_analyzer import IsortAnalyzer, IsortFinding


INSECURE_ISORT = """\
[settings]
profile = black
honor_noqa = false
skip = src, lib
skip_gitignore = false
force_sort_within_sections = false
known_third_party = []
api_key = hardcoded_secret_value_12345
"""

HARDENED_ISORT = """\
[settings]
profile = black
honor_noqa = true
skip_gitignore = true
force_sort_within_sections = true
known_first_party = myproject
"""


class TestIsortAnalyzer:
    def test_detects_insecure_isort(self, tmp_path: Path):
        (tmp_path / ".isort.cfg").write_text(INSECURE_ISORT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "honor_noqa_false" in kinds
        assert "skip_source" in kinds
        assert "black_profile_skip_gitignore" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_isort_scores_well(self, tmp_path: Path):
        (tmp_path / ".isort.cfg").write_text(HARDENED_ISORT, encoding="utf-8")
        analyzer = IsortAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].profile == "black"

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = IsortAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = IsortFinding(
            kind="honor_noqa_false",
            severity="high",
            message="test message",
            path=".isort.cfg",
            lineno=3,
            line="honor_noqa = false",
        )
        assert ".isort.cfg:3" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = IsortAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.isort]" in template
        assert "honor_noqa = true" in template

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".isort.cfg").write_text(
            "[settings]\nhonor_noqa = false\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        isort = next(c for c in report.categories if c.name == "isort")
        assert isort.score < 100.0
        assert isort.details.get("findings", 0) > 0
