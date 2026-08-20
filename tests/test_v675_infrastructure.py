"""Tests for v6.75.0 infrastructure analyzers."""

from pathlib import Path

from devai import CirrusCIAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_PIPELINE = """
task:
  ubuntu_instance:
    image: ubuntu:24.04

  test_script: |
    pip install -e '.[dev]'
    python -m pytest
"""


class TestV675InfrastructureAnalyzers:
    def test_facade_cirrus_ci(self, tmp_path: Path):
        (tmp_path / ".cirrus.yml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = DevAI.mock().cirrus_ci(tmp_path)
        assert isinstance(analyzer, CirrusCIAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_cirrus_ci_category(self, tmp_path: Path):
        (tmp_path / ".cirrus.yml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "cirrus_ci" in names
