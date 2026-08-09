"""Tests for KubernetesAnalyzer."""

from pathlib import Path

from devai.kubernetes_analyzer import KubernetesAnalyzer, KubernetesFinding


GOOD_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: app
          image: ghcr.io/org/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
"""


class TestKubernetesAnalyzer:
    def test_no_manifests_returns_empty(self, tmp_path: Path):
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary().lower()

    def test_clean_deployment(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(GOOD_DEPLOYMENT, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not findings
        stats = analyzer.stats
        assert stats.manifests == 1
        assert stats.resources >= 1
        assert analyzer.health_score() == 100.0

    def test_detects_privileged(self, tmp_path: Path):
        k8s = tmp_path / "kubernetes"
        k8s.mkdir()
        manifest = GOOD_DEPLOYMENT.replace(
            "allowPrivilegeEscalation: false",
            "privileged: true\n            allowPrivilegeEscalation: false",
        )
        (k8s / "deployment.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "privileged" for f in findings)

    def test_detects_host_network(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        manifest = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  hostNetwork: true\n"
        (k8s / "pod.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "host_network" for f in findings)

    def test_detects_latest_tag(self, tmp_path: Path):
        k8s = tmp_path / "manifests"
        k8s.mkdir()
        manifest = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n"
            "spec:\n  template:\n    spec:\n      containers:\n"
            "        - name: app\n          image: nginx:latest\n"
        )
        (k8s / "deployment.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "latest_image_tag" for f in findings)

    def test_detects_secret_in_env(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        manifest = (
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
            "stringData:\n  password: mysecretpassword123\n"
        )
        (k8s / "secret.yaml").write_text(manifest, encoding="utf-8")
        findings = KubernetesAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "secret_in_env" for f in findings)

    def test_finding_format(self):
        finding = KubernetesFinding(
            kind="test",
            severity="high",
            message="msg",
            path="k8s/deployment.yaml",
            lineno=5,
            resource="Deployment/app",
        )
        assert "Deployment/app" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        template = KubernetesAnalyzer(str(tmp_path)).generate_hardened_template()
        assert "runAsNonRoot: true" in template
        assert "allowPrivilegeEscalation: false" in template

    def test_to_context(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  hostPID: true\n",
            encoding="utf-8",
        )
        context = KubernetesAnalyzer(str(tmp_path)).to_context()
        assert "Kubernetes manifest analysis" in context
        assert "host_pid" in context or "hostPID" in context
