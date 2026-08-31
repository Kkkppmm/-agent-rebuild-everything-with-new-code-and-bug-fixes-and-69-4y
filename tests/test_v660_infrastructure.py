"""Tests for v6.60.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, WoodpeckerCIAnalyzer


class TestV660InfrastructureAnalyzers:
    def test_facade_woodpecker_ci(self, tmp_path: Path):
        (tmp_path / ".woodpecker.yml").write_text(
            "when:\n  - event: push\n    branch: main\n"
            "steps:\n  - name: test\n    image: python:3.12-slim\n"
            "    commands:\n      - python -m pytest\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().woodpecker_ci(tmp_path)
        assert isinstance(analyzer, WoodpeckerCIAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_woodpecker_ci_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".woodpecker.yml").write_text(
            "when:\n  - event: push\n    branch: main\n"
            "steps:\n  - name: test\n    image: python:3.12-slim\n"
            "    commands:\n      - python -m pytest\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "woodpecker_ci" in names
