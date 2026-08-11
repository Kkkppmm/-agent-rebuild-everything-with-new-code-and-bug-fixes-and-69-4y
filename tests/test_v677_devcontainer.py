"""Tests for v6.77.0 DevContainerAnalyzer integration."""

from pathlib import Path

from devai import DevAI, DevContainerAnalyzer


class TestV677DevContainerIntegration:
    def test_facade_devcontainer(self, tmp_path: Path):
        dev_dir = tmp_path / ".devcontainer"
        dev_dir.mkdir()
        (dev_dir / "devcontainer.json").write_text(
            '{"name": "test", "image": "python:3.12", "remoteUser": "vscode"}',
            encoding="utf-8",
        )
        analyzer = DevAI.mock().devcontainer(tmp_path)
        assert isinstance(analyzer, DevContainerAnalyzer)
        assert analyzer.stats.containers == 1

    def test_project_health_includes_devcontainer_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        dev_dir = tmp_path / ".devcontainer"
        dev_dir.mkdir()
        (dev_dir / "devcontainer.json").write_text(
            '{"name": "test", "image": "python:3.12", "remoteUser": "vscode"}',
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "devcontainer" in names
