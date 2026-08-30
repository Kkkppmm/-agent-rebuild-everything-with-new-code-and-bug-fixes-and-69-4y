"""Tests for ArgoWorkflowsAnalyzer."""

from pathlib import Path

from devai.argo_workflows_analyzer import ArgoWorkflowsAnalyzer, ArgoWorkflowsFinding


INSECURE_CONFIG = """
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: insecure-workflow-
spec:
  entrypoint: main
  arguments:
    parameters:
      - name: git-url
        value: https://github.com/example/repo
  templates:
    - name: main
      steps:
        - - name: build
            template: build-step
        - - name: security-scan
            template: security-scan

    - name: build-step
      container:
        image: golang:latest
        command: [sh, -c]
        args:
          - |
            curl -sSL http://install.example.com/setup.sh | bash
            echo "Building {{workflow.parameters.git-url}}"
            docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock
        env:
          - name: API_KEY
            value: "sk-abcdefghijklmnopqrstuvwxyz1234567890"
        securityContext:
          runAsUser: 0
          privileged: true
          allowPrivilegeEscalation: true
        hostNetwork: true
        hostPID: true

    - name: security-scan
      container:
        image: alpine:latest
        command: [sh, -c, "devai security-scan ."]
        continueOn:
          failed: true
"""

HARDENED_CONFIG = """
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: hardened-workflow-
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
        env:
          - name: PYPI_TOKEN
            valueFrom:
              secretKeyRef:
                name: pypi-credentials
                key: token
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
"""


class TestArgoWorkflowsAnalyzer:
    def test_no_argo_files(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
        analyzer = ArgoWorkflowsAnalyzer(str(tmp_path))
        assert analyzer.stats.workflows == 0
        assert analyzer.health_score() == 100.0

    def test_finds_argo_config(self, tmp_path: Path):
        argo_dir = tmp_path / ".argo"
        argo_dir.mkdir()
        (argo_dir / "workflow.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = ArgoWorkflowsAnalyzer(str(tmp_path))
        assert analyzer.stats.workflows == 1

    def test_insecure_vs_hardened(self, tmp_path: Path):
        argo_dir = tmp_path / ".argo"
        argo_dir.mkdir()
        (argo_dir / "workflow.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")

        insecure = ArgoWorkflowsAnalyzer(str(tmp_path))
        insecure_score = insecure.health_score()
        insecure_findings = insecure.analyze()

        (argo_dir / "workflow.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        hardened = ArgoWorkflowsAnalyzer(str(tmp_path))
        hardened_score = hardened.health_score()

        assert len(insecure_findings) > 0
        assert insecure_score < hardened_score

    def test_finding_types(self, tmp_path: Path):
        argo_dir = tmp_path / ".argo"
        argo_dir.mkdir()
        (argo_dir / "workflow.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        findings = ArgoWorkflowsAnalyzer(str(tmp_path)).analyze()
        kinds = {f.kind for f in findings}
        assert all(isinstance(f, ArgoWorkflowsFinding) for f in findings)
        assert "hardcoded_secret" in kinds or "hardcoded_env" in kinds or "plain_secret_value" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "host_namespace" in kinds

    def test_generate_template(self, tmp_path: Path):
        analyzer = ArgoWorkflowsAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "ArgoWorkflowsAnalyzer" in template
        assert "secretKeyRef" in template
        assert "runAsNonRoot" in template

    def test_summary_and_context(self, tmp_path: Path):
        argo_dir = tmp_path / ".argo"
        argo_dir.mkdir()
        (argo_dir / "workflow.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = ArgoWorkflowsAnalyzer(str(tmp_path))
        assert "Argo Workflows:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_finding_format(self, tmp_path: Path):
        argo_dir = tmp_path / ".argo"
        argo_dir.mkdir()
        (argo_dir / "workflow.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = ArgoWorkflowsAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert finding.format().startswith("[")
