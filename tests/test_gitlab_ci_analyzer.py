"""Tests for GitLabCIAnalyzer."""

from pathlib import Path

from devai.gitlab_ci_analyzer import GitLabCIAnalyzer, GitLabCIFinding

INSECURE_GITLAB_CI = """
stages:
  - test
  - deploy

variables:
  API_SECRET: supersecret
  DEPLOY_TOKEN: hardcoded-token

include:
  - remote: https://example.com/ci-template.yml

default:
  image: node:latest

services:
  - name: docker:24-dind
    privileged: true

test:
  stage: test
  only:
    - main
  allow_failure: true
  script:
    - curl -fsSL https://example.com/install.sh | bash
    - echo "$CI_COMMIT_MESSAGE" | tee /tmp/msg.txt
  artifacts:
    access: all

deploy:
  stage: deploy
  when: manual
  script:
    - ./deploy.sh
"""

HARDENED_GITLAB_CI = """
stages:
  - test

variables:
  PIP_DISABLE_PIP_VERSION_CHECK: "1"

default:
  image: python:3.12-slim

test:
  stage: test
  script:
    - pip install -e ".[dev]"
    - python -m pytest
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""


class TestGitLabCIAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(INSECURE_GITLAB_CI, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_variables" in kinds
        assert "curl_pipe_shell" in kinds
        assert "unpinned_image" in kinds
        assert "privileged_service" in kinds
        assert "docker_in_docker" in kinds
        assert "remote_include" in kinds
        assert "deprecated_only_except" in kinds
        assert "allow_failure" in kinds
        assert "public_artifact_access" in kinds
        assert "manual_deploy" in kinds
        assert "untrusted_input_in_script" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(HARDENED_GITLAB_CI, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1
        assert "test" in analyzer.infos[0].jobs

    def test_finding_format(self):
        finding = GitLabCIFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".gitlab-ci.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert ".gitlab-ci.yml:1" in finding.format()

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "stages:" in template
        assert "python:3.12-slim" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(HARDENED_GITLAB_CI, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "GitLab CI analysis:" in context
        assert "health score" in context

    def test_nested_gitlab_ci_file(self, tmp_path: Path):
        ci_dir = tmp_path / "ci"
        ci_dir.mkdir()
        (ci_dir / "pipeline.gitlab-ci.yml").write_text(HARDENED_GITLAB_CI, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
