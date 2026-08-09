"""Tests for MakefileAnalyzer, KubernetesAnalyzer, TerraformAnalyzer, and NginxAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer
from devai.kubernetes_analyzer import KubernetesAnalyzer
from devai.terraform_analyzer import TerraformAnalyzer
from devai.nginx_analyzer import NginxAnalyzer


INSECURE_MAKEFILE = """
deploy:
\trm -rf /
\tcurl -fsSL https://example.com/install.sh | bash
\tAPI_SECRET=supersecret
\tchmod 777 /tmp/app
\tgit push origin main --force
"""

SAFE_MAKEFILE = """
help:
\t@echo "Targets: build test"

build:
\tpython -m build

test:
\tpytest
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
        image: nginx:latest
        securityContext:
          privileged: true
          runAsUser: 0
        env:
        - name: API_KEY
          value: supersecret
"""

SAFE_K8S = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
      - name: app
        image: nginx:1.25.3
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
"""


INSECURE_TERRAFORM = """
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  acl = "public-read"
}

resource "aws_db_instance" "db" {
  password = "hardcodedpassword"
  encrypted = false
  publicly_accessible = false
}
"""


INSECURE_NGINX = """
server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1;
    server_tokens on;
    autoindex on;
    add_header Access-Control-Allow-Origin "*";
    proxy_pass http://backend:8080;
    ssl off;
}
"""

SAFE_NGINX = """
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000";
    add_header X-Content-Type-Options nosniff;
    proxy_pass https://backend:8443;
}
"""


class TestMakefileAnalyzer:
    def test_no_makefiles(self, tmp_path: Path):
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert analyzer.stats.makefiles == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(INSECURE_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "dangerous_rm" in kinds
        assert "curl_pipe_shell" in kinds
        assert "secret_in_makefile" in kinds
        assert "chmod_777" in kinds
        assert analyzer.health_score() < 50.0

    def test_safe_makefile(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(SAFE_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert not any(f.severity == "high" for f in analyzer.analyze())
        assert analyzer.infos[0].has_help is True


class TestKubernetesAnalyzer:
    def test_no_manifests(self, tmp_path: Path):
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(INSECURE_K8S, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "latest_tag" in kinds
        assert analyzer.health_score() < 50.0

    def test_safe_manifest(self, tmp_path: Path):
        k8s_dir = tmp_path / "kubernetes"
        k8s_dir.mkdir()
        (k8s_dir / "app.yaml").write_text(SAFE_K8S, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert not any(f.severity == "high" for f in analyzer.analyze())


class TestTerraformAnalyzer:
    def test_no_terraform(self, tmp_path: Path):
        analyzer = TerraformAnalyzer(str(tmp_path))
        assert analyzer.stats.files == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(INSECURE_TERRAFORM, encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "open_security_group" in kinds
        assert "public_acl" in kinds
        assert "hardcoded_secret" in kinds
        assert "encryption_disabled" in kinds
        assert analyzer.health_score() < 50.0


class TestNginxAnalyzer:
    def test_no_configs(self, tmp_path: Path):
        analyzer = NginxAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        nginx_dir = tmp_path / "nginx"
        nginx_dir.mkdir()
        (nginx_dir / "site.conf").write_text(INSECURE_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "weak_tls" in kinds
        assert "server_tokens_on" in kinds
        assert "wildcard_cors" in kinds
        assert analyzer.health_score() < 50.0

    def test_safe_config(self, tmp_path: Path):
        nginx_dir = tmp_path / "nginx"
        nginx_dir.mkdir()
        (nginx_dir / "default.conf").write_text(SAFE_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        assert not any(f.severity == "high" for f in analyzer.analyze())
        assert analyzer.infos[0].has_ssl is True
