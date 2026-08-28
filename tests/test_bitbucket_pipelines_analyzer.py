"""Tests for BitbucketPipelinesAnalyzer."""

from pathlib import Path

from devai.bitbucket_pipelines_analyzer import (
    BitbucketPipelinesAnalyzer,
    BitbucketPipelinesFinding,
)


INSECURE_PIPELINE = """
image: node:latest

pipelines:
  default:
    - step:
        name: Build
        services:
          - docker
        script:
          - curl -sSL http://install.example.com/setup.sh | bash
          - docker run -v /var/run/docker.sock:/var/run/docker.sock alpine echo ok
          - sudo apt-get update
        variables:
          API_TOKEN: "sk-live-hardcoded-secret"

  pull-requests:
    '**':
      - step:
          name: Test PR
          script:
            - echo Branch $BITBUCKET_BRANCH for PR $BITBUCKET_PR_ID

  custom:
    security-scan:
      - step:
          name: Security scan
          trigger: manual
          script:
            - echo scan
"""

HARDENED_PIPELINE = """
image: python:3.12-slim

pipelines:
  default:
    - step:
        name: Test
        script:
          - pip install -e ".[dev]"
          - python -m pytest
"""


def _write_bitbucket_pipelines(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "bitbucket-pipelines.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestBitbucketPipelinesAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = BitbucketPipelinesAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_pipeline(self, tmp_path: Path):
        _write_bitbucket_pipelines(tmp_path, INSECURE_PIPELINE)
        analyzer = BitbucketPipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "latest_image_tag" in kinds
        assert "docker_socket_mount" in kinds
        assert "sudo_usage" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pipeline_few_findings(self, tmp_path: Path):
        _write_bitbucket_pipelines(tmp_path, HARDENED_PIPELINE)
        analyzer = BitbucketPipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_bitbucket_pipelines(tmp_path, HARDENED_PIPELINE)
        analyzer = BitbucketPipelinesAnalyzer(str(tmp_path))
        assert "Bitbucket Pipelines:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = BitbucketPipelinesAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "pipelines:" in template
        assert "Security scan" in template

    def test_finding_format(self):
        finding = BitbucketPipelinesFinding(
            kind="test",
            severity="high",
            message="test message",
            path="bitbucket-pipelines.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
