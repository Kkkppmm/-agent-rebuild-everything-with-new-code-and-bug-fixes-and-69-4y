"""Tests for v6.59.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, DroneCIAnalyzer


class TestV659InfrastructureAnalyzers:
    def test_facade_drone_ci(self, tmp_path: Path):
        (tmp_path / ".drone.yml").write_text(
            "kind: pipeline\ntype: docker\nname: default\n"
            "steps:\n  - name: test\n    image: python:3.12-slim\n"
            "    commands:\n      - python -m pytest\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().drone_ci(tmp_path)
        assert isinstance(analyzer, DroneCIAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_drone_ci_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".drone.yml").write_text(
            "kind: pipeline\ntype: docker\nname: default\n"
            "steps:\n  - name: test\n    image: python:3.12-slim\n"
            "    commands:\n      - python -m pytest\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "drone_ci" in names
