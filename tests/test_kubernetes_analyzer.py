"""Tests for KubernetesAnalyzer."""

from pathlib import Path

from devai.kubernetes_analyzer import KubernetesAnalyzer


GOOD_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: app
          image: ghcr.io/org/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
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

    def test_clean_deployment(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(GOOD_DEPLOYMENT, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        stats = analyzer.stats
        assert stats.manifests == 1
        assert stats.resources >= 1
        assert analyzer.health_score() >= 90.0

    def test_detects_privileged(self, tmp_path: Path):
        manifest = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: bad\n"
            "spec:\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: nginx:1.25\n"
            "      securityContext:\n"
            "        privileged: true\n"
        )
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "privileged" for f in findings)

    def test_detects_host_network(self, tmp_path: Path):
        manifest = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: bad\n"
            "spec:\n"
            "  hostNetwork: true\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: nginx:1.25\n"
        )
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "host_network" for f in findings)

    def test_detects_run_as_root(self, tmp_path: Path):
        manifest = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: bad\n"
            "spec:\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: nginx:1.25\n"
            "      securityContext:\n"
            "        runAsUser: 0\n"
        )
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "run_as_root" for f in findings)

    def test_detects_latest_tag(self, tmp_path: Path):
        manifest = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: bad\n"
            "spec:\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: nginx:latest\n"
        )
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "latest_tag" for f in findings)

    def test_detects_secret_in_env(self, tmp_path: Path):
        manifest = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: bad\n"
            "spec:\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: nginx:1.25\n"
            "      env:\n"
            "        - name: API_KEY\n"
            "          value: 'sk_live_abc123secret'\n"
        )
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "secret_in_env" for f in findings)

    def test_detects_sensitive_hostpath(self, tmp_path: Path):
        manifest = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: bad\n"
            "spec:\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: nginx:1.25\n"
            "  volumes:\n"
            "    - name: docker-sock\n"
            "      hostPath:\n"
            "        path: /var/run/docker.sock\n"
        )
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "sensitive_hostpath" for f in findings)

    def test_detects_missing_security_context(self, tmp_path: Path):
        manifest = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: app\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: app\n"
            "          image: nginx:1.25\n"
        )
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "missing_security_context" for f in findings)

    def test_generate_template(self, tmp_path: Path):
        analyzer = KubernetesAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "apiVersion:" in template
        assert "runAsNonRoot" in template
        assert "secretKeyRef" in template

    def test_to_context(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(GOOD_DEPLOYMENT, encoding="utf-8")
        context = KubernetesAnalyzer(str(tmp_path)).to_context()
        assert "Kubernetes manifest analysis" in context
        assert "health score" in context
