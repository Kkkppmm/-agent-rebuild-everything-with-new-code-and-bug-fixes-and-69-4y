"""Tests for v6.77.0 DevContainerAnalyzer integration."""

from pathlib import Path

from devai import DevAI, DevContainerAnalyzer
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """
{
  "name": "Hardened Dev Container",
  "image": "mcr.microsoft.com/devcontainers/python:1-3.12-bookworm",
  "remoteUser": "vscode",
  "postCreateCommand": "pip install -r requirements.txt"
}
"""


class TestV677DevContainerAnalyzer:
    def test_facade_devcontainer(self, tmp_path: Path):
        dev_dir = tmp_path / ".devcontainer"
        dev_dir.mkdir()
        (dev_dir / "devcontainer.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().devcontainer(tmp_path)
        assert isinstance(analyzer, DevContainerAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_devcontainer_category(self, tmp_path: Path):
        dev_dir = tmp_path / ".devcontainer"
        dev_dir.mkdir()
        (dev_dir / "devcontainer.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "devcontainer" in names
