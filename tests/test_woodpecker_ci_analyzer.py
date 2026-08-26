"""Tests for WoodpeckerCIAnalyzer."""

from pathlib import Path

from devai.woodpecker_ci_analyzer import WoodpeckerCIAnalyzer, WoodpeckerCIFinding


INSECURE_CONFIG = """
when:
  - event: push
    branch: $WOODPECKER_BRANCH

steps:
  - name: build
    image: golang:latest
    user: root
    privileged: true
    network_mode: host
    environment:
      API_TOKEN: "sk-live-hardcoded-secret"
    commands:
      - curl -sSL http://install.example.com/setup.sh | bash
      - echo Deploying $WOODPECKER_BRANCH from $WOODPECKER_PULL_REQUEST
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
when:
  - event: push
    branch: main
  - event: pull_request

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


def _write_woodpecker_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / ".woodpecker.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestWoodpeckerCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = WoodpeckerCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_woodpecker_config(tmp_path, INSECURE_CONFIG)
        analyzer = WoodpeckerCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "host_network" in kinds
        assert "docker_socket_mount" in kinds
        assert "trusted_mode" not in kinds  # not in this config
        assert "script_injection" in kinds
        assert "sensitive_volume" in kinds
        assert "security_failure_ignored" in kinds
        assert "root_user" in kinds
        assert "unsafe_when_condition" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_woodpecker_config(tmp_path, HARDENED_CONFIG)
        analyzer = WoodpeckerCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        _write_woodpecker_config(tmp_path, INSECURE_CONFIG)
        analyzer = WoodpeckerCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(isinstance(f, WoodpeckerCIFinding) for f in findings)
        assert all(f.path == ".woodpecker.yml" for f in findings)
        assert all("[high]" in f.format() or "[medium]" in f.format() or "[low]" in f.format() for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        _write_woodpecker_config(tmp_path, HARDENED_CONFIG)
        analyzer = WoodpeckerCIAnalyzer(str(tmp_path))
        assert "Woodpecker CI: 1 file(s)" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Woodpecker CI pipeline analysis:" in ctx
        assert "health score: 100.0/100" in ctx

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = WoodpeckerCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "steps:" in template
        assert "security-scan" in template

    def test_woodpecker_dir_detection(self, tmp_path: Path):
        ci_dir = tmp_path / ".woodpecker"
        ci_dir.mkdir()
        (ci_dir / "pipeline.yml").write_text(
            "steps:\n  - name: test\n    image: python:3.12-slim\n",
            encoding="utf-8",
        )
        analyzer = WoodpeckerCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1
