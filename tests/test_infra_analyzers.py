"""Tests for infrastructure analyzers (Makefile, Kubernetes, Terraform, Nginx, Helm)."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer
from devai.kubernetes_analyzer import KubernetesAnalyzer
from devai.terraform_analyzer import TerraformAnalyzer
from devai.nginx_analyzer import NginxAnalyzer
from devai.helm_analyzer import HelmAnalyzer


INSECURE_MAKEFILE = """
install:
\tcurl -fsSL https://example.com/install.sh | bash
\tAPI_SECRET=hardcoded
\tsudo apt-get install -y
\tgit push origin main --force
\tchmod 777 /tmp
"""

HARDENED_MAKEFILE = """
.PHONY: install test clean

install:
\tpip install -r requirements.txt

test:
\tpytest

clean:
\trm -rf build dist
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
            - name: API_SECRET
              value: supersecret
"""

HARDENED_K8S = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: app
          image: myregistry/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
"""


INSECURE_TF = """
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  acl = "public-read"
}

resource "aws_db_instance" "db" {
  password             = "hardcoded"
  publicly_accessible  = true
  skip_final_snapshot  = true
}
"""

HARDENED_TF = """
resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_versioning" "data" {
  versioning_configuration {
    status = "Enabled"
  }
}
"""


INSECURE_NGINX = """
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
    server_tokens on;
    autoindex on;
    add_header Access-Control-Allow-Origin *;
    location / {
        proxy_pass http://backend:8080;
    }
}
"""

HARDENED_NGINX = """
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate /etc/ssl/cert.pem;
    server_tokens off;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000" always;
    location / {
        proxy_pass https://backend:8443;
    }
}
"""


def _write_helm_chart(tmp_path: Path, values: str, template: str) -> Path:
    chart = tmp_path / "charts" / "myapp"
    chart.mkdir(parents=True)
    (chart / "Chart.yaml").write_text("name: myapp\nversion: 0.1.0\n", encoding="utf-8")
    (chart / "values.yaml").write_text(values, encoding="utf-8")
    templates = chart / "templates"
    templates.mkdir()
    (templates / "deployment.yaml").write_text(template, encoding="utf-8")
    return chart


INSECURE_HELM_VALUES = """
image:
  repository: myapp
  tag: latest
apiKey: hardcoded-secret
"""

INSECURE_HELM_TEMPLATE = """
spec:
  hostNetwork: true
  containers:
    - securityContext:
        privileged: true
        runAsUser: 0
      volumeMounts:
        - mountPath: /data
  volumes:
    - hostPath:
        path: /host
"""

HARDENED_HELM_VALUES = """
image:
  repository: myregistry/app
  tag: "1.0.0"
"""

HARDENED_HELM_TEMPLATE = """
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
    - securityContext:
        allowPrivilegeEscalation: false
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
        assert "curl_pipe_shell" in kinds
        assert "secret_in_makefile" in kinds
        assert "sudo_usage" in kinds
        assert "git_force_push" in kinds
        assert "chmod_777" in kinds

    def test_hardened_makefile(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(HARDENED_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert not any(f.severity == "high" for f in analyzer.analyze())
        assert analyzer.infos[0].has_phony is True


class TestKubernetesAnalyzer:
    def test_no_manifests(self, tmp_path: Path):
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(INSECURE_K8S, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "latest_tag" in kinds
        assert "run_as_root" in kinds
        assert "secret_in_env" in kinds

    def test_hardened_manifest(self, tmp_path: Path):
        k8s = tmp_path / "kubernetes"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(HARDENED_K8S, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert not any(f.severity == "high" for f in analyzer.analyze())


class TestTerraformAnalyzer:
    def test_no_files(self, tmp_path: Path):
        analyzer = TerraformAnalyzer(str(tmp_path))
        assert analyzer.stats.files == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(INSECURE_TF, encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "open_security_group" in kinds
        assert "public_acl" in kinds
        assert "hardcoded_secret" in kinds
        assert "publicly_accessible" in kinds

    def test_hardened_terraform(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(HARDENED_TF, encoding="utf-8")
        analyzer = TerraformAnalyzer(str(tmp_path))
        assert not any(f.severity == "high" for f in analyzer.analyze())


class TestNginxAnalyzer:
    def test_no_configs(self, tmp_path: Path):
        analyzer = NginxAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        nginx = tmp_path / "nginx"
        nginx.mkdir()
        (nginx / "site.conf").write_text(INSECURE_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "weak_tls" in kinds
        assert "wildcard_cors" in kinds
        assert "insecure_proxy_pass" in kinds
        assert "autoindex" in kinds

    def test_hardened_nginx(self, tmp_path: Path):
        nginx = tmp_path / "nginx"
        nginx.mkdir()
        (nginx / "site.conf").write_text(HARDENED_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        assert not any(f.severity == "high" for f in analyzer.analyze())
        assert analyzer.infos[0].has_ssl is True


class TestHelmAnalyzer:
    def test_no_charts(self, tmp_path: Path):
        analyzer = HelmAnalyzer(str(tmp_path))
        assert analyzer.stats.charts == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        _write_helm_chart(tmp_path, INSECURE_HELM_VALUES, INSECURE_HELM_TEMPLATE)
        analyzer = HelmAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "latest_tag" in kinds
        assert "hardcoded_secret" in kinds
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "host_path" in kinds

    def test_hardened_chart(self, tmp_path: Path):
        _write_helm_chart(tmp_path, HARDENED_HELM_VALUES, HARDENED_HELM_TEMPLATE)
        analyzer = HelmAnalyzer(str(tmp_path))
        assert not any(f.severity == "high" for f in analyzer.analyze())
        assert analyzer.infos[0].name == "myapp"

    def test_summary_and_template(self, tmp_path: Path):
        _write_helm_chart(tmp_path, HARDENED_HELM_VALUES, HARDENED_HELM_TEMPLATE)
        analyzer = HelmAnalyzer(str(tmp_path))
        assert "Helm charts:" in analyzer.summary()
        assert "runAsNonRoot" in analyzer.generate_hardened_template()
