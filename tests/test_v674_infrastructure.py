"""Tests for v6.74.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, GoCDCIAnalyzer
from devai.project_health import ProjectHealth


HARDENED_PIPELINE = """
format_version: 10
pipelines:
  hardened-pipeline:
    group: defaultGroup
    materials:
      git:
        url: https://github.com/org/repo.git
        branch: main
    stages:
      - test:
          jobs:
            unit-tests:
              tasks:
                - exec:
                    command: bash
                    arguments:
                      - -c
                      - python -m pytest
"""


class TestV674InfrastructureAnalyzers:
    def test_facade_gocd_ci(self, tmp_path: Path):
        gocd_dir = tmp_path / ".gocd"
        gocd_dir.mkdir()
        (gocd_dir / "pipelines.yaml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = DevAI.mock().gocd_ci(tmp_path)
        assert isinstance(analyzer, GoCDCIAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_gocd_ci_category(self, tmp_path: Path):
        gocd_dir = tmp_path / ".gocd"
        gocd_dir.mkdir()
        (gocd_dir / "pipelines.yaml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "gocd_ci" in names
