"""Tests for CodefreshAnalyzer."""

from pathlib import Path

from devai.codefresh_analyzer import CodefreshAnalyzer, CodefreshFinding


INSECURE_CONFIG = """
version: "1.0"
stages:
  - build
  - deploy

steps:
  build_app:
    stage: build
    image: golang:latest
    user: root
    privileged: true
    network_mode: host
    environment:
      API_TOKEN: "sk-live-hardcoded-secret"
    commands:
      - curl -sSL http://install.example.com/setup.sh | bash
      - echo Deploying ${CF_BRANCH} from PR ${CF_PULL_REQUEST_NUMBER}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /root/.ssh:/root/.ssh

  security_audit:
    stage: build
    title: security-audit
    image: python:3.12-slim
    commands:
      - bandit -r .
    fail_fast: false

  deploy_prod:
    stage: deploy
    image: alpine:latest
    when:
      branch: "*"
    commands:
      - cf_export_variable DEPLOY_KEY my-deploy-key
"""

HARDENED_CONFIG = """
version: "1.0"
stages:
  - test
  - security

steps:
  test:
    stage: test
    title: Run tests
    image: python:3.12-slim
    commands:
      - pip install -e ".[dev]"
      - python -m pytest

  security_scan:
    stage: security
    title: Security scan
    image: python:3.12-slim
    commands:
      - pip install devai
      - devai security-scan .
    when:
      branch:
        - main
"""


def _write_codefresh_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "codefresh.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestCodefreshAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CodefreshAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_insecure_config_has_high_findings(self, tmp_path: Path):
        _write_codefresh_config(tmp_path, INSECURE_CONFIG)
        analyzer = CodefreshAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "docker_socket_mount" in kinds
        assert analyzer.stats.high_severity >= 4
        assert analyzer.health_score() < 50.0

    def test_hardened_config_has_few_findings(self, tmp_path: Path):
        _write_codefresh_config(tmp_path, HARDENED_CONFIG)
        analyzer = CodefreshAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        _write_codefresh_config(tmp_path, INSECURE_CONFIG)
        analyzer = CodefreshAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(isinstance(f, CodefreshFinding) for f in findings)
        assert all(f.path == "codefresh.yml" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        _write_codefresh_config(tmp_path, HARDENED_CONFIG)
        analyzer = CodefreshAnalyzer(str(tmp_path))
        assert "Codefresh: 1 file(s)" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Codefresh pipeline analysis:" in ctx

    def test_generate_template(self, tmp_path: Path):
        analyzer = CodefreshAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "version:" in template
        assert "security_scan" in template

    def test_codefresh_dir_detection(self, tmp_path: Path):
        ci_dir = tmp_path / ".codefresh"
        ci_dir.mkdir()
        (ci_dir / "pipeline.yaml").write_text(
            "version: '1.0'\nsteps:\n  test:\n    image: python:3.12-slim\n",
            encoding="utf-8",
        )
        analyzer = CodefreshAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1
