"""Tests for v6.73.0 infrastructure analyzers."""

from pathlib import Path

from devai import AppVeyorCIAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """
version: 1.0.{build}
image: Visual Studio 2022

environment:
  matrix:
    - PYTHON: "C:\\Python312"

build_script:
  - "%PYTHON%\\python.exe -m pytest"
"""


class TestV673InfrastructureAnalyzers:
    def test_facade_appveyor_ci(self, tmp_path: Path):
        (tmp_path / "appveyor.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().appveyor_ci(tmp_path)
        assert isinstance(analyzer, AppVeyorCIAnalyzer)
        assert analyzer.stats.configs == 1

    def test_project_health_includes_appveyor_ci_category(self, tmp_path: Path):
        (tmp_path / "appveyor.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "appveyor_ci" in names
