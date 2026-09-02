"""Tests for v6.52.0 infrastructure analyzers."""

from pathlib import Path

from devai import AnsibleAnalyzer, DevAI


class TestV652InfrastructureAnalyzers:
    def test_facade_ansible(self, tmp_path: Path):
        ansible_dir = tmp_path / "ansible"
        ansible_dir.mkdir()
        (ansible_dir / "site.yml").write_text(
            "- hosts: localhost\n  tasks: []\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().ansible(tmp_path)
        assert isinstance(analyzer, AnsibleAnalyzer)
        assert analyzer.stats.files == 1

    def test_project_health_includes_ansible_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        ansible_dir = tmp_path / "playbooks"
        ansible_dir.mkdir()
        (ansible_dir / "deploy.yml").write_text(
            "- hosts: web\n  tasks: []\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "ansible" in names
