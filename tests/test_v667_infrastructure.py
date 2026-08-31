"""Tests for v6.67.0 infrastructure analyzers."""

from pathlib import Path

from devai import ArgoWorkflowsAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_ARGO = """
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: test-workflow-
spec:
  entrypoint: main
  templates:
    - name: main
      steps:
        - - name: test
            template: pytest

    - name: pytest
      container:
        image: python:3.12-slim
        command: [python, -m, pytest]
        securityContext:
          runAsNonRoot: true
"""


class TestV667InfrastructureAnalyzers:
    def test_facade_argo_workflows(self, tmp_path: Path):
        argo_dir = tmp_path / ".argo"
        argo_dir.mkdir()
        (argo_dir / "workflow.yaml").write_text(HARDENED_ARGO, encoding="utf-8")
        analyzer = DevAI.mock().argo_workflows(tmp_path)
        assert isinstance(analyzer, ArgoWorkflowsAnalyzer)
        assert analyzer.stats.workflows == 1

    def test_project_health_includes_argo_workflows_category(self, tmp_path: Path):
        argo_dir = tmp_path / ".argo"
        argo_dir.mkdir()
        (argo_dir / "workflow.yaml").write_text(HARDENED_ARGO, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "argo_workflows" in names
