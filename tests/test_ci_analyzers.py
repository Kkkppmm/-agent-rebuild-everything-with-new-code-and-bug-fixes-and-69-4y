"""Tests for CI/CD platform analyzers."""

from pathlib import Path

from devai.gitlab_ci_analyzer import GitLabCIAnalyzer
from devai.circleci_analyzer import CircleCIAnalyzer
from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer
from devai.bitbucket_pipelines_analyzer import BitbucketPipelinesAnalyzer
from devai.kubernetes_analyzer import K8sAnalyzer

INSECURE_GITLAB_CI = """
stages:
  - build
build:
  image: node:latest
  variables:
    API_SECRET: supersecret
  script:
    - curl -fsSL https://example.com/install.sh | bash
    - echo "$CI_COMMIT_MESSAGE"
  services:
    - docker:dind
  before_script:
    - docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock alpine
"""

INSECURE_CIRCLECI = """
version: 2.1
orbs:
  python: circleci/python@2
jobs:
  build:
    docker:
      - image: cimg/python:latest
    environment:
      API_TOKEN: hardcoded-secret
    steps:
      - run: curl -fsSL https://example.com/install.sh | bash
      - run: docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock alpine
"""

INSECURE_JENKINSFILE = """
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'curl -fsSL https://example.com/install.sh | bash'
                sh "echo ${params.SCRIPT}"
                echo ${PASSWORD}
            }
            environment {
                PASSWORD = 'hardcoded'
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
        name: Build
        variables:
          API_KEY: supersecret
        script:
          - curl -fsSL https://example.com/install.sh | bash
        services:
          - docker:
              privileged: true
              volumes:
                - /var/run/docker.sock:/var/run/docker.sock
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
      hostPID: true
      containers:
        - name: app
          image: myapp:latest
          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
          env:
            - name: API_KEY
              value: "hardcoded-secret"
          volumeMounts:
            - mountPath: /data
              name: host-vol
      volumes:
        - name: host-vol
          hostPath:
            path: /etc
"""


class TestGitLabCIAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(INSECURE_GITLAB_CI, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "secret_in_variables" in kinds
        assert "curl_pipe_shell" in kinds
        assert "docker_sock" in kinds
        assert analyzer.health_score() < 50.0


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
        kinds = {f.kind for f in analyzer.analyze()}
        assert "secret_in_environment" in kinds
        assert "curl_pipe_shell" in kinds
        assert "latest_image" in kinds


class TestJenkinsfileAnalyzer:
    def test_no_jenkinsfile_returns_perfect_score(self, tmp_path: Path):
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.jenkinsfiles == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(INSECURE_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "curl_pipe_shell" in kinds
        assert "hardcoded_credential" in kinds
        assert "credentials_in_echo" in kinds


class TestBitbucketPipelinesAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = BitbucketPipelinesAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "bitbucket-pipelines.yml").write_text(INSECURE_BITBUCKET, encoding="utf-8")
        analyzer = BitbucketPipelinesAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "secret_in_variables" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged" in kinds


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
        kinds = {f.kind for f in analyzer.analyze()}
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "host_path" in kinds
        assert "latest_image" in kinds
        assert "secret_in_env" in kinds

    def test_generate_template(self, tmp_path: Path):
        analyzer = K8sAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "runAsNonRoot: true" in template
        assert "allowPrivilegeEscalation: false" in template

    def test_to_context(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(INSECURE_K8S, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Kubernetes manifest analysis" in context
        assert "health score" in context
