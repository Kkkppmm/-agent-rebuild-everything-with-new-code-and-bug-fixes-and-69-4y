"""Tests for v6.61.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, CodefreshAnalyzer


class TestV661InfrastructureAnalyzers:
    def test_facade_codefresh(self, tmp_path: Path):
        (tmp_path / "codefresh.yml").write_text(
            "version: '1.0'\n"
            "stages:\n  - test\n"
            "steps:\n  test:\n    stage: test\n    image: python:3.12-slim\n"
            "    commands:\n      - python -m pytest\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().codefresh(tmp_path)
        assert isinstance(analyzer, CodefreshAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_codefresh_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "codefresh.yml").write_text(
            "version: '1.0'\n"
            "stages:\n  - test\n"
            "steps:\n  test:\n    stage: test\n    image: python:3.12-slim\n"
            "    commands:\n      - python -m pytest\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "codefresh" in names
