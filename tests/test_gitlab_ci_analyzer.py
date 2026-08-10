"""Tests for GitLabCIAnalyzer."""

from pathlib import Path

from devai.gitlab_ci_analyzer import GitLabCIAnalyzer, GitLabFinding

INSECURE_GITLAB = """
stages:
  - test
  - deploy

variables:
  API_SECRET: 'supersecret'

test:
  image: python
  script:
    - curl -fsSL https://example.com/install.sh | bash
    - sudo apt-get update
    - echo $CI_COMMIT_MESSAGE

deploy:
  image: alpine:latest
  stage: deploy
  services:
    - docker:dind
  variables:
    DOCKER_TLS_CERTDIR: ""
  script:
    - eval $DEPLOY_SCRIPT
  privileged: true
"""

HARDENED_GITLAB = """
stages:
  - test

test:
  stage: test
  image: python:3.12.0-slim
  only:
    - main
    - merge_requests
  script:
    - pip install -e ".[dev]"
    - python -m pytest
"""


class TestGitLabCIAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "no config" in analyzer.summary().lower()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(INSECURE_GITLAB, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_variables" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_usage" in kinds
        assert "dangerous_script" in kinds
        assert "privileged_container" in kinds
        assert "dind_tls_disabled" in kinds
        assert "untrusted_ci_var" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(HARDENED_GITLAB, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.config_files == 1
        assert analyzer.infos[0].job_count >= 1

    def test_finding_format(self):
        finding = GitLabFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".gitlab-ci.yml",
            lineno=1,
            line="test line",
        )
        assert "[high]" in finding.format()
        assert ".gitlab-ci.yml:1" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "stages:" in template
        assert "python -m pytest" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(INSECURE_GITLAB, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "GitLab CI configuration analysis" in context
        assert "health score" in context
