"""Tests for v6.57.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, TravisCIAnalyzer


class TestV657InfrastructureAnalyzers:
    def test_facade_travis_ci(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(
            "language: python\npython:\n  - \"3.12\"\nscript: pytest\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().travis_ci(tmp_path)
        assert isinstance(analyzer, TravisCIAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_travis_ci_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".travis.yml").write_text(
            "language: python\npython:\n  - \"3.12\"\nscript: pytest\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "travis_ci" in names
