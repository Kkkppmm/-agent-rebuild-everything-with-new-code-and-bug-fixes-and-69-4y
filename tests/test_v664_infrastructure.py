"""Tests for v6.64.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, TeamCityAnalyzer


class TestV664InfrastructureAnalyzers:
    def test_facade_teamcity(self, tmp_path: Path):
        tc_dir = tmp_path / ".teamcity"
        tc_dir.mkdir()
        (tc_dir / "settings.kts").write_text(
            'version = "2024.03"\n'
            "project {\n"
            '    buildType(BuildType { id("Tests"); name = "Tests" })\n'
            "}\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().teamcity(tmp_path)
        assert isinstance(analyzer, TeamCityAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_teamcity_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        tc_dir = tmp_path / ".teamcity"
        tc_dir.mkdir()
        (tc_dir / "settings.kts").write_text(
            'version = "2024.03"\n'
            "project {\n"
            '    buildType(BuildType { id("Tests"); name = "Tests" })\n'
            "}\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "teamcity" in names
