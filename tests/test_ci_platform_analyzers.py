"""Tests for CircleCI, GitLab CI, Jenkins, Bitbucket Pipelines, and K8s analyzers."""

from pathlib import Path

from devai.circleci_analyzer import CircleCIAnalyzer
from devai.gitlab_ci_analyzer import GitLabCIAnalyzer
from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer
from devai.bitbucket_pipelines_analyzer import BitbucketPipelinesAnalyzer
from devai.kubernetes_analyzer import K8sAnalyzer

INSECURE_CIRCLECI = """
version: 2.1
orbs:
  python: circleci/python@main
jobs:
  build:
    docker:
      - image: cimg/python:latest
    environment:
      API_SECRET: hardcoded
    steps:
      - run: curl -fsSL https://example.com/install.sh | bash
"""

INSECURE_GITLAB_CI = """
stages:
  - test
variables:
  DB_PASSWORD: secret123
test:
  image: python:latest
  script:
    - curl -fsSL https://example.com/install.sh | bash
"""

INSECURE_JENKINSFILE = """
pipeline {
    stages {
        stage('Build') {
            steps {
                sh 'password=secret123'
                sh 'curl -fsSL https://example.com/install.sh | bash'
            }
        }
    }
}
"""

INSECURE_BITBUCKET = """
image: python:latest
pipelines:
  default:
    - step:
        script:
          - API_KEY=hardcoded
          - curl -fsSL https://example.com/install.sh | bash
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
          securityContext:
            privileged: true
            runAsUser: 0
          env:
            - name: DB_PASSWORD
              value: secret123
"""


class TestCircleCIAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = CircleCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        circleci = tmp_path / ".circleci"
        circleci.mkdir()
        (circleci / "config.yml").write_text(INSECURE_CIRCLECI, encoding="utf-8")
        analyzer = CircleCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unpinned_orb" in kinds
        assert "latest_image" in kinds
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.health_score() < 50.0


class TestGitLabCIAnalyzer:
    def test_no_pipeline_returns_perfect_score(self, tmp_path: Path):
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(INSECURE_GITLAB_CI, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "latest_image" in kinds
        assert "secret_in_variables" in kinds
        assert "curl_pipe_shell" in kinds


class TestJenkinsfileAnalyzer:
    def test_no_jenkinsfile_returns_perfect_score(self, tmp_path: Path):
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(INSECURE_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds


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
        assert "latest_image" in kinds
        assert "secret_in_config" in kinds
        assert "curl_pipe_shell" in kinds


class TestK8sAnalyzer:
    def test_no_manifests_returns_perfect_score(self, tmp_path: Path):
        analyzer = K8sAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(INSECURE_K8S, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "latest_image" in kinds
        assert "privileged_container" in kinds
        assert "host_network" in kinds
        assert "run_as_root" in kinds
        assert "secret_in_env" in kinds
        assert analyzer.health_score() < 50.0

    def test_summary_and_template(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(INSECURE_K8S, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        assert "Kubernetes:" in analyzer.summary()
        assert "manifest analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "runAsNonRoot: true" in template
