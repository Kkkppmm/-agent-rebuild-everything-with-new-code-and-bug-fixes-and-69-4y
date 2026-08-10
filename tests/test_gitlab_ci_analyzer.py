"""Tests for GitLabCIAnalyzer."""

from pathlib import Path

from devai.gitlab_ci_analyzer import GitLabCIAnalyzer, GitLabCIFinding

INSECURE_CONFIG = """
stages:
  - build
variables:
  API_SECRET: supersecret
build:
  stage: build
  image: python:latest
  services:
    - name: docker:latest
  script:
    - curl -fsSL https://example.com/install.sh | bash
    - echo "$(CI_COMMIT_MESSAGE)"
  artifacts:
    when: always
deploy:
  stage: deploy
  image: alpine:3.19
  variables:
    DOCKER_HOST: unix:///var/run/docker.sock
  script:
    - docker build .
  tags:
    - docker
"""

HARDENED_CONFIG = """
stages:
  - test

test:
  stage: test
  image: python:3.12.7-slim-bookworm
  script:
    - pip install -e ".[dev]"
    - python -m pytest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
"""


class TestGitLabCIAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_variables" in kinds
        assert "latest_image" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1

    def test_generate_template(self, tmp_path: Path):
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "stages:" in template
        assert "python:3.12" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "GitLab CI config analysis" in context

    def test_finding_format(self):
        finding = GitLabCIFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".gitlab-ci.yml",
            lineno=1,
            job="build",
        )
        assert "build" in finding.format()
