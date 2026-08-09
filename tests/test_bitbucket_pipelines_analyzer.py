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
        script:
          - curl -sSL http://install.example.com/setup.sh | bash
          - docker run -v /var/run/docker.sock:/var/run/docker.sock alpine echo ok
          - echo Deploying $BITBUCKET_BRANCH
        services:
          - docker:
              privileged: true

  pull-requests:
    '**':
      - step:
          name: Security scan
          allow-failure: true
          script:
            - echo scan

definitions:
  variables:
    API_TOKEN: "sk-live-hardcoded-secret"
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
        assert "privileged_service" in kinds
        assert "docker_socket_mount" in kinds
        assert "latest_image_tag" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pipeline_few_findings(self, tmp_path: Path):
        _write_bitbucket_pipelines(tmp_path, HARDENED_PIPELINE)
        analyzer = BitbucketPipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_generate_hardened_template(self):
        snippet = BitbucketPipelinesAnalyzer(".").generate_hardened_template()
        assert "pipelines:" in snippet
        assert "Security scan" in snippet

    def test_finding_format(self):
        finding = BitbucketPipelinesFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="bitbucket-pipelines.yml",
            lineno=1,
        )
        assert "bitbucket-pipelines.yml:1" in finding.format()
