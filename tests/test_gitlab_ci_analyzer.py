"""Tests for GitLabCIAnalyzer."""

from pathlib import Path

from devai.gitlab_ci_analyzer import GitLabCIAnalyzer, GitLabCIFinding


INSECURE_PIPELINE = """
stages:
  - build
  - security

variables:
  API_TOKEN: "sk-live-hardcoded-secret"

build:
  image: node:latest
  services:
    - name: docker:dind
      privileged: true
  script:
    - curl -sSL http://install.example.com/setup.sh | bash
    - docker run -v /var/run/docker.sock:/var/run/docker.sock alpine echo ok
    - echo Deploying $CI_COMMIT_REF_NAME
  rules:
    - merge_requests

security_scan:
  stage: security
  script:
    - echo scan
  allow_failure: true
"""

HARDENED_PIPELINE = """
stages:
  - test

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

test:
  stage: test
  image: python:3.12-slim
  script:
    - pip install -e ".[dev]"
    - python -m pytest
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""


def _write_gitlab_ci(tmp_path: Path, content: str, name: str = ".gitlab-ci.yml") -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


class TestGitLabCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_pipeline(self, tmp_path: Path):
        _write_gitlab_ci(tmp_path, INSECURE_PIPELINE)
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_service" in kinds
        assert "docker_socket_mount" in kinds
        assert "latest_image_tag" in kinds
        assert "security_allow_failure" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pipeline_few_findings(self, tmp_path: Path):
        _write_gitlab_ci(tmp_path, HARDENED_PIPELINE)
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_finds_gitlab_ci_variants(self, tmp_path: Path):
        ci_dir = tmp_path / ".gitlab" / "ci"
        ci_dir.mkdir(parents=True)
        (ci_dir / "deploy.gitlab-ci.yml").write_text(
            "deploy:\n  script: echo deploy\n",
            encoding="utf-8",
        )
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines >= 1

    def test_generate_hardened_template(self):
        snippet = GitLabCIAnalyzer(".").generate_hardened_template()
        assert "stages:" in snippet
        assert "allow_failure: false" in snippet

    def test_finding_format(self):
        finding = GitLabCIFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path=".gitlab-ci.yml",
            lineno=1,
        )
        assert ".gitlab-ci.yml:1" in finding.format()
