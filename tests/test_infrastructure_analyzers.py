"""Tests for infrastructure analyzers (GitLab CI, Jenkins, Ansible, Helm, Nginx, K8s)."""

from pathlib import Path

from devai.gitlab_ci_analyzer import GitLabCIAnalyzer
from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer
from devai.ansible_analyzer import AnsibleAnalyzer
from devai.helm_analyzer import HelmAnalyzer
from devai.nginx_analyzer import NginxAnalyzer
from devai.kubernetes_analyzer import K8sAnalyzer

INSECURE_GITLAB_CI = """
stages:
  - build
variables:
  API_SECRET: supersecret123
build:
  image: node:latest
  services:
    - docker:dind
  variables:
    DOCKER_PRIVILEGED: "true"
  script:
    - curl -fsSL https://example.com/install.sh | bash
    - echo "${CI_COMMIT_MESSAGE}"
  privileged: true
"""

INSECURE_JENKINSFILE = """
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'curl -fsSL https://example.com/install.sh | bash'
        sh "echo ${params.USER_INPUT}"
        sh 'password = "hardcoded_secret_value"'
      }
    }
    stage('Docker') {
      steps {
        sh 'docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock myapp:latest'
      }
    }
  }
}
"""

INSECURE_ANSIBLE = """
- hosts: all
  become: true
  vars:
    db_password: "plaintext_password"
  tasks:
    - name: Run command
      shell: echo {{ user_input }}
    - name: Create file
      file:
        path: /tmp/data
        mode: '0777'
"""

INSECURE_HELM_VALUES = """
image:
  repository: myapp
  tag: latest
password: "hardcoded_secret"
securityContext:
  privileged: true
  runAsUser: 0
  allowPrivilegeEscalation: true
hostNetwork: true
"""

INSECURE_NGINX = """
server {
  listen 443;
  ssl off;
  ssl_protocols TLSv1 TLSv1.1;
  autoindex on;
  server_tokens on;
  allow all;
  location / {
    proxy_pass http://backend:8080;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
"""

INSECURE_K8S = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: default
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
            allowPrivilegeEscalation: true
          env:
            - name: API_KEY
              value: "hardcoded_secret_key"
          resources: {}
"""


class TestGitLabCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(INSECURE_GITLAB_CI, encoding="utf-8")
        analyzer = GitLabCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_variables" in kinds or "plain_secret" in kinds
        assert "latest_image_tag" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.health_score() < 50.0


class TestJenkinsfileAnalyzer:
    def test_no_jenkinsfiles_returns_perfect_score(self, tmp_path: Path):
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.jenkinsfiles == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(INSECURE_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "script_injection" in kinds
        assert "privileged_docker" in kinds or "docker_sock_mount" in kinds
        assert analyzer.health_score() < 50.0


class TestAnsibleAnalyzer:
    def test_no_playbooks_returns_perfect_score(self, tmp_path: Path):
        analyzer = AnsibleAnalyzer(str(tmp_path))
        assert analyzer.stats.playbooks == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        playbook_dir = tmp_path / "ansible"
        playbook_dir.mkdir()
        (playbook_dir / "deploy.yml").write_text(INSECURE_ANSIBLE, encoding="utf-8")
        analyzer = AnsibleAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "shell_injection" in kinds or "shell_task" in kinds
        assert "weak_file_mode" in kinds
        assert analyzer.health_score() < 50.0


class TestHelmAnalyzer:
    def test_no_charts_returns_perfect_score(self, tmp_path: Path):
        analyzer = HelmAnalyzer(str(tmp_path))
        assert analyzer.stats.charts == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        chart = tmp_path / "mychart" / "templates"
        chart.mkdir(parents=True)
        (chart / "deployment.yaml").write_text(INSECURE_HELM_VALUES, encoding="utf-8")
        analyzer = HelmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "latest_image_tag" in kinds
        assert "privileged_pod" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 50.0


class TestNginxAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = NginxAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "nginx.conf").write_text(INSECURE_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "ssl_disabled" in kinds
        assert "weak_ssl_protocol" in kinds
        assert "proxy_pass_http" in kinds
        assert analyzer.health_score() < 50.0


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
        assert "privileged_pod" in kinds
        assert "host_network" in kinds
        assert "latest_image_tag" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 50.0

    def test_summary_and_context(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(INSECURE_K8S, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        assert "manifest" in analyzer.summary()
        assert "Kubernetes" in analyzer.to_context()
