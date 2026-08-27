"""Tests for v6.71.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, HarnessCIAnalyzer
from devai.project_health import ProjectHealth


HARDENED_PIPELINE = """
pipeline:
  name: Hardened Pipeline
  identifier: Hardened_Pipeline
  stages:
    - stage:
        name: Build
        identifier: Build
        type: CI
        spec:
          infrastructure:
            type: KubernetesDirect
            spec:
              connectorRef: account.DevCluster
              namespace: harness-delegate
              automountServiceAccountToken: false
              os: Linux
          execution:
            steps:
              - step:
                  type: Run
                  name: Test
                  identifier: Test
                  spec:
                    connectorRef: account.dockerhub
                    image: python:3.12-slim
                    shell: Sh
                    command: python -m pytest
"""


class TestV671InfrastructureAnalyzers:
    def test_facade_harness_ci(self, tmp_path: Path):
        harness_dir = tmp_path / ".harness"
        harness_dir.mkdir()
        (harness_dir / "pipeline.yaml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = DevAI.mock().harness_ci(tmp_path)
        assert isinstance(analyzer, HarnessCIAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_harness_ci_category(self, tmp_path: Path):
        harness_dir = tmp_path / ".harness"
        harness_dir.mkdir()
        (harness_dir / "pipeline.yaml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "harness_ci" in names
