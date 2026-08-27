"""Tests for TektonAnalyzer."""

from pathlib import Path

from devai.tekton_analyzer import TektonAnalyzer, TektonFinding


INSECURE_CONFIG = """
apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: insecure-pipeline
spec:
  params:
    - name: git-url
      type: string
  workspaces:
    - name: shared-workspace
  tasks:
    - name: build
      taskSpec:
        workspaces:
          - name: source
            workspace: shared-workspace
        steps:
          - name: setup
            image: golang:latest
            script: |
              curl -sSL http://install.example.com/setup.sh | bash
              echo "Building $(params.git-url)"
              docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock
            env:
              - name: API_KEY
                value: "sk-abcdefghijklmnopqrstuvwxyz1234567890"
            securityContext:
              runAsUser: 0
              privileged: true
              allowPrivilegeEscalation: true

    - name: security-scan
      runAfter:
        - build
      taskSpec:
        steps:
          - name: scan
            image: alpine:latest
            script: devai security-scan .
            onError: continue
"""

HARDENED_CONFIG = """
apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: hardened-pipeline
spec:
  params:
    - name: git-url
      type: string
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
            workingDir: $(workspaces.source.path)
            script: |
              pip install -e ".[dev]"
              python -m pytest
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


class TestTektonAnalyzer:
    def test_no_tekton_files(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
        analyzer = TektonAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_finds_tekton_config(self, tmp_path: Path):
        tekton_dir = tmp_path / ".tekton"
        tekton_dir.mkdir()
        (tekton_dir / "pipeline.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = TektonAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1

    def test_insecure_vs_hardened(self, tmp_path: Path):
        tekton_dir = tmp_path / ".tekton"
        tekton_dir.mkdir()
        (tekton_dir / "pipeline.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")

        insecure = TektonAnalyzer(str(tmp_path))
        insecure_score = insecure.health_score()
        insecure_findings = insecure.analyze()

        (tekton_dir / "pipeline.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        hardened = TektonAnalyzer(str(tmp_path))
        hardened_score = hardened.health_score()

        assert len(insecure_findings) > 0
        assert insecure_score < hardened_score

    def test_finding_types(self, tmp_path: Path):
        tekton_dir = tmp_path / ".tekton"
        tekton_dir.mkdir()
        (tekton_dir / "pipeline.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        findings = TektonAnalyzer(str(tmp_path)).analyze()
        kinds = {f.kind for f in findings}
        assert all(isinstance(f, TektonFinding) for f in findings)
        assert "hardcoded_secret" in kinds or "hardcoded_env" in kinds or "plain_secret_value" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds

    def test_generate_template(self, tmp_path: Path):
        analyzer = TektonAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "TektonAnalyzer" in template
        assert "secretKeyRef" in template
        assert "runAsNonRoot" in template

    def test_summary_and_context(self, tmp_path: Path):
        tekton_dir = tmp_path / ".tekton"
        tekton_dir.mkdir()
        (tekton_dir / "pipeline.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = TektonAnalyzer(str(tmp_path))
        assert "Tekton:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_finding_format(self, tmp_path: Path):
        tekton_dir = tmp_path / ".tekton"
        tekton_dir.mkdir()
        (tekton_dir / "pipeline.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = TektonAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert finding.format().startswith("[")
