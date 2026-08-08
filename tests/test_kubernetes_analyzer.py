"""Tests for KubernetesAnalyzer."""

from pathlib import Path

from devai.kubernetes_analyzer import KubernetesAnalyzer, KubernetesFinding


GOOD_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: app
          image: ghcr.io/example/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
"""


class TestKubernetesAnalyzer:
    def test_no_manifests_returns_empty(self, tmp_path: Path):
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert "no manifests" in analyzer.summary().lower()

    def test_clean_manifest(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(GOOD_DEPLOYMENT, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not findings
        stats = analyzer.stats
        assert stats.manifests == 1
        assert stats.resources >= 1
        assert analyzer.health_score() == 100.0

    def test_detects_privileged(self, tmp_path: Path):
        manifest = """\
apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        privileged: true
"""
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "privileged" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_host_network(self, tmp_path: Path):
        manifest = """\
apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.25
"""
        k8s_dir = tmp_path / "kubernetes"
        k8s_dir.mkdir()
        (k8s_dir / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "host_network" for f in findings)

    def test_detects_latest_tag(self, tmp_path: Path):
        manifest = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
"""
        k8s_dir = tmp_path / "manifests"
        k8s_dir.mkdir()
        (k8s_dir / "deploy.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "latest_tag" for f in findings)

    def test_detects_secret_in_env(self, tmp_path: Path):
        manifest = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          env:
            - name: API_KEY
              value: sk_live_secret123
"""
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deploy.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "secret_in_env" for f in findings)

    def test_detects_run_as_root(self, tmp_path: Path):
        manifest = """\
apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  securityContext:
    runAsUser: 0
  containers:
    - name: app
      image: nginx:1.25
"""
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "run_as_root" for f in findings)

    def test_detects_docker_socket(self, tmp_path: Path):
        manifest = """\
apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
  containers:
    - name: app
      image: nginx:1.25
"""
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "docker_socket" for f in findings)

    def test_generate_template(self):
        template = KubernetesAnalyzer(".").generate_hardened_template()
        assert "runAsNonRoot: true" in template
        assert "capabilities:" in template

    def test_to_context(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(GOOD_DEPLOYMENT, encoding="utf-8")
        context = KubernetesAnalyzer(str(tmp_path)).to_context()
        assert "Kubernetes manifest analysis" in context
        assert "health score" in context

    def test_finding_format(self):
        finding = KubernetesFinding(
            kind="privileged",
            severity="high",
            message="test",
            path="k8s/pod.yaml",
            lineno=5,
            resource="Pod/bad",
        )
        assert "Pod/bad" in finding.format()
        assert "high" in finding.format()
