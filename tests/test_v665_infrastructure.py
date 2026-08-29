"""Tests for v6.65.0 infrastructure analyzers."""

from pathlib import Path

from devai import CloudBuildAnalyzer, DevAI


class TestV665InfrastructureAnalyzers:
    def test_facade_cloud_build(self, tmp_path: Path):
        (tmp_path / "cloudbuild.yaml").write_text(
            "steps:\n"
            "  - id: test\n"
            "    name: python:3.12-slim\n"
            "    entrypoint: bash\n"
            "    args:\n"
            "      - -c\n"
            "      - python -m pytest\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().cloud_build(tmp_path)
        assert isinstance(analyzer, CloudBuildAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_cloud_build_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "cloudbuild.yaml").write_text(
            "steps:\n"
            "  - id: test\n"
            "    name: python:3.12-slim\n"
            "    entrypoint: bash\n"
            "    args:\n"
            "      - -c\n"
            "      - python -m pytest\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "cloud_build" in names
