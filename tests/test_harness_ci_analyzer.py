"""Tests for HarnessCIAnalyzer."""

from pathlib import Path

from devai.harness_ci_analyzer import HarnessCIAnalyzer, HarnessCIFinding


INSECURE_CONFIG = """
pipeline:
  name: Insecure Pipeline
  identifier: Insecure_Pipeline
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
              namespace: harness
              automountServiceAccountToken: true
              os: Linux
          execution:
            steps:
              - step:
                  type: Run
                  name: Deploy
                  identifier: Deploy
                  spec:
                    connectorRef: account.dockerhub
                    image: golang:latest
                    privileged: true
                    hostNetwork: true
                    runAsUser: 0
                    allowPrivilegeEscalation: true
                    shell: Sh
                    command: |-
                      curl -sSL http://install.example.com/setup.sh | bash
                      echo Deploying <+codebase.pullRequest.title>
                    volumes:
                      - /var/run/docker.sock:/var/run/docker.sock
                  variables:
                    - name: API_TOKEN
                      type: String
                      value: "sk-live-hardcoded-secret"

              - step:
                  type: Run
                  name: security-audit
                  identifier: security_audit
                  spec:
                    connectorRef: account.dockerhub
                    image: python:3.12-slim
                    shell: Sh
                    command: bandit -r .
                  failureStrategies:
                    - onFailure:
                        errors:
                          - AllErrors
                        action:
                          type: Ignore
"""

HARDENED_CONFIG = """
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
                    command: |-
                      pip install -e ".[dev]"
                      python -m pytest

              - step:
                  type: Run
                  name: Security Scan
                  identifier: Security_Scan
                  spec:
                    connectorRef: account.dockerhub
                    image: python:3.12-slim
                    shell: Sh
                    command: |-
                      pip install devai
                      devai security-scan .
"""


def _write_harness_config(tmp_path: Path, content: str) -> Path:
    harness_dir = tmp_path / ".harness"
    harness_dir.mkdir()
    path = harness_dir / "pipeline.yaml"
    path.write_text(content, encoding="utf-8")
    return path


class TestHarnessCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_harness_config(tmp_path, INSECURE_CONFIG)
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "plaintext_secret_type" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "host_network" in kinds
        assert "run_as_root" in kinds
        assert "docker_socket_mount" in kinds
        assert "automount_sa_token" in kinds
        assert "script_injection" in kinds
        assert "privilege_escalation" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_harness_config(tmp_path, HARDENED_CONFIG)
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_harness_config(tmp_path, HARDENED_CONFIG)
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        assert "Harness CI:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = HarnessCIAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "pipeline:" in template
        assert "Security Scan" in template

    def test_finding_format(self):
        finding = HarnessCIFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="pipeline.yaml",
            lineno=1,
        )
        assert "[high]" in finding.format()
