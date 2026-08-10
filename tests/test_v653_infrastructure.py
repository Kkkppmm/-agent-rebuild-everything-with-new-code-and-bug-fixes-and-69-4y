"""Tests for v6.53.0 infrastructure analyzers."""

from pathlib import Path

from devai import AzurePipelinesAnalyzer, DevAI


class TestV653InfrastructureAnalyzers:
    def test_facade_azure_pipelines(self, tmp_path: Path):
        (tmp_path / "azure-pipelines.yml").write_text(
            "trigger:\n  - main\npool:\n  vmImage: ubuntu-latest\nsteps:\n"
            "  - script: echo hello\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().azure_pipelines(tmp_path)
        assert isinstance(analyzer, AzurePipelinesAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_azure_pipelines_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "azure-pipelines.yml").write_text(
            "trigger:\n  - main\npool:\n  vmImage: ubuntu-latest\nsteps:\n"
            "  - script: echo hello\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "azure_pipelines" in names
