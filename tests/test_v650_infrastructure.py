"""Tests for v6.50.0 infrastructure analyzers."""

from pathlib import Path

from devai import (
    DevAI,
    KubernetesAnalyzer,
    MakefileAnalyzer,
    NginxAnalyzer,
    TerraformAnalyzer,
)


class TestV650InfrastructureAnalyzers:
    def test_facade_makefile(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text("test:\n\tpython -m pytest\n", encoding="utf-8")
        analyzer = DevAI.mock().makefile(tmp_path)
        assert isinstance(analyzer, MakefileAnalyzer)
        assert analyzer.stats.makefiles == 1

    def test_facade_kubernetes(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "pod.yaml").write_text("kind: Pod\n", encoding="utf-8")
        analyzer = DevAI.mock().kubernetes(tmp_path)
        assert isinstance(analyzer, KubernetesAnalyzer)
        assert analyzer.stats.manifests == 1

    def test_facade_terraform(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text('variable "name" {}\n', encoding="utf-8")
        analyzer = DevAI.mock().terraform(tmp_path)
        assert isinstance(analyzer, TerraformAnalyzer)
        assert analyzer.stats.terraform_files == 1

    def test_facade_nginx(self, tmp_path: Path):
        (tmp_path / "nginx.conf").write_text("server {}\n", encoding="utf-8")
        analyzer = DevAI.mock().nginx(tmp_path)
        assert isinstance(analyzer, NginxAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_new_categories(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "Makefile").write_text("test:\n\ttrue\n", encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "makefile" in names
        assert "kubernetes" in names
        assert "terraform" in names
        assert "nginx" in names
