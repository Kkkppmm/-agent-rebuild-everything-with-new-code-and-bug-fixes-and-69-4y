"""Tests for CI and infrastructure analyzers."""

from pathlib import Path

from devai.circleci_analyzer import CircleCIAnalyzer
from devai.bitbucket_pipelines_analyzer import BitbucketPipelinesAnalyzer
from devai.gitlab_ci_analyzer import GitLabCIAnalyzer
from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer
from devai.kubernetes_analyzer import K8sAnalyzer

INSECURE_CIRCLECI = """
version: 2.1
orbs:
  python: circleci/python@main
jobs:
  build:
    docker:
      - image: cimg/python:latest
        privileged: true
    environment:
      API_SECRET: hardcoded-secret
    steps:
      - run: curl -fsSL https://example.com/install.sh | bash
"""

INSECURE_BITBUCKET = """
image: python:latest
pipelines:
  default:
    - step:
        script:
          - pipe: atlassian/slack-notify@main
          - curl https://example.com/setup.sh | bash
variables:
  API_KEY: supersecret
"""

INSECURE_GITLAB = """
stages:
  - test
variables:
  DB_PASSWORD: mypassword123
test:
  image: python:latest
  script:
    - curl https://example.com/install.sh | bash
  services:
    - name: docker:dind
      privileged: true
"""

INSECURE_JENKINSFILE = """
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'curl https://example.com/setup.sh | bash'
                sh "echo ${env.BUILD_NUMBER}"
            }
            environment {
                PASSWORD = 'hardcoded'
            }
        }
    }
}
"""

INSECURE_K8S = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: myapp:latest
          privileged: true
          securityContext:
            runAsUser: 0
          env:
            - name: API_KEY
              value: "hardcoded-secret"
"""


class TestCircleCIAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = CircleCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        config_dir = tmp_path / ".circleci"
        config_dir.mkdir()
        (config_dir / "config.yml").write_text(INSECURE_CIRCLECI, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unpinned_orb" in kinds
        assert "secret_in_env" in kinds
        assert "privileged_docker" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.health_score() < 50.0


class TestBitbucketPipelinesAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = BitbucketPipelinesAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "bitbucket-pipelines.yml").write_text(INSECURE_BITBUCKET, encoding="utf-8")
        analyzer = BitbucketPipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unpinned_pipe" in kinds
        assert "secret_in_variables" in kinds
        assert "curl_pipe_shell" in kinds


class TestGitLabCIAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(INSECURE_GITLAB, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "latest_image" in kinds
        assert "secret_in_variables" in kinds
        assert "privileged_docker" in kinds
        assert "curl_pipe_shell" in kinds


class TestJenkinsfileAnalyzer:
    def test_no_jenkinsfile_returns_perfect_score(self, tmp_path: Path):
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.jenkinsfiles == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(INSECURE_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "inline_credential" in kinds
        assert "curl_pipe_shell" in kinds
        assert "unsafe_sh_interpolation" in kinds


class TestK8sAnalyzer:
    def test_no_manifests_returns_perfect_score(self, tmp_path: Path):
        analyzer = K8sAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(INSECURE_K8S, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "run_as_root" in kinds
        assert "latest_image" in kinds
        assert "secret_env_literal" in kinds
        assert analyzer.health_score() < 50.0

    def test_template_and_context(self, tmp_path: Path):
        k8s_dir = tmp_path / "kubernetes"
        k8s_dir.mkdir()
        (k8s_dir / "app.yaml").write_text(INSECURE_K8S, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        assert "Kubernetes:" in analyzer.summary()
        assert "manifest analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "runAsNonRoot: true" in template
