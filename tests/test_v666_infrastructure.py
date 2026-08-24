"""Tests for v6.66.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, TektonAnalyzer
from devai.project_health import ProjectHealth


HARDENED_TEKTON = """
apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: test-pipeline
spec:
  workspaces:
    - name: shared-workspace
  tasks:
    - name: test
      taskSpec:
        workspaces:
          - name: source
            workspace: shared-workspace
        steps:
          - name: pytest
            image: python:3.12-slim
            script: python -m pytest
            securityContext:
              runAsNonRoot: true
"""


class TestV666InfrastructureAnalyzers:
    def test_facade_tekton(self, tmp_path: Path):
        tekton_dir = tmp_path / ".tekton"
        tekton_dir.mkdir()
        (tekton_dir / "pipeline.yaml").write_text(HARDENED_TEKTON, encoding="utf-8")
        analyzer = DevAI.mock().tekton(tmp_path)
        assert isinstance(analyzer, TektonAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_tekton_category(self, tmp_path: Path):
        tekton_dir = tmp_path / ".tekton"
        tekton_dir.mkdir()
        (tekton_dir / "pipeline.yaml").write_text(HARDENED_TEKTON, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "tekton" in names
