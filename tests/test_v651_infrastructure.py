"""Tests for v6.51.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, HelmAnalyzer


class TestV651InfrastructureAnalyzers:
    def test_facade_helm(self, tmp_path: Path):
        chart = tmp_path / "charts" / "api"
        chart.mkdir(parents=True)
        (chart / "Chart.yaml").write_text("name: api\nversion: 0.1.0\n", encoding="utf-8")
        (chart / "values.yaml").write_text("replicaCount: 1\n", encoding="utf-8")
        analyzer = DevAI.mock().helm(tmp_path)
        assert isinstance(analyzer, HelmAnalyzer)
        assert analyzer.stats.charts == 1

    def test_project_health_includes_helm_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        chart = tmp_path / "helm" / "web"
        chart.mkdir(parents=True)
        (chart / "Chart.yaml").write_text("name: web\nversion: 0.1.0\n", encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "helm" in names
