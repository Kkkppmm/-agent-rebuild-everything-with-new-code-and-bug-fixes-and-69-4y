"""Tests for DroneCIAnalyzer."""

from pathlib import Path

from devai.drone_ci_analyzer import DroneCIAnalyzer, DroneCIFinding


INSECURE_CONFIG = """
kind: pipeline
type: docker
name: default
trusted: true

steps:
  - name: build
    image: golang:latest
  - name: install
    image: alpine:latest
    privileged: true
    network_mode: host
    environment:
      API_TOKEN: "sk-live-hardcoded-secret"
      DRONE_TLS_VERIFY: false
    commands:
      - curl -sSL http://install.example.com/setup.sh | bash
      - echo Deploying $DRONE_BRANCH from $DRONE_PULL_REQUEST
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /root/.ssh:/root/.ssh

  - name: security-audit
    image: python:3.12-slim
    commands:
      - bandit -r .
    failure: ignore

  - name: plugin-deploy
    image: plugins/docker
    settings:
      repo: myorg/myapp
      tags: latest

plugins:
  - name: example/deploy
    tag: master
"""

HARDENED_CONFIG = """
kind: pipeline
type: docker
name: default

steps:
  - name: test
    image: python:3.12-slim
    commands:
      - pip install -e ".[dev]"
      - python -m pytest

  - name: security-scan
    image: python:3.12-slim
    commands:
      - pip install devai
      - devai security-scan .
    depends_on:
      - test
"""


def _write_drone_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / ".drone.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestDroneCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = DroneCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_drone_config(tmp_path, INSECURE_CONFIG)
        analyzer = DroneCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "host_network" in kinds
        assert "docker_socket_mount" in kinds
        assert "tls_verify_disabled" in kinds
        assert "trusted_mode" in kinds
        assert "script_injection" in kinds
        assert "sensitive_volume" in kinds
        assert "security_failure_ignored" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_drone_config(tmp_path, HARDENED_CONFIG)
        analyzer = DroneCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_drone_config(tmp_path, HARDENED_CONFIG)
        analyzer = DroneCIAnalyzer(str(tmp_path))
        assert "Drone CI:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = DroneCIAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "kind: pipeline" in template
        assert "security-scan" in template

    def test_finding_format(self):
        finding = DroneCIFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".drone.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
