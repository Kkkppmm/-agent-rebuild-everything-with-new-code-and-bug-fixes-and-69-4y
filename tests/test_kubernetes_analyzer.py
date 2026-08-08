"""Tests for KubernetesAnalyzer."""

from pathlib import Path

from devai.kubernetes_analyzer import KubernetesAnalyzer, KubernetesFinding


INSECURE_MANIFEST = """
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
          image: nginx:latest
          privileged: true
          env:
            - name: API_KEY
              value: supersecret
          volumeMounts:
            - name: docker-sock
              mountPath: /var/run/docker.sock
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
"""

HARDENED_MANIFEST = """
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
          image: ghcr.io/example/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
"""


class TestKubernetesAnalyzer:
    def test_no_manifests_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert analyzer.stats.manifest_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "latest_tag" in kinds
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "host_pid" in kinds
        assert "secret_in_env" in kinds
        assert "docker_sock_mount" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_manifest_scores_well(self, tmp_path: Path):
        k8s = tmp_path / "kubernetes"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.manifest_files == 1
        assert analyzer.infos[0].has_security_context is True

    def test_summary_context_and_template(self, tmp_path: Path):
        k8s = tmp_path / "manifests"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert "Kubernetes manifests:" in analyzer.summary()
        assert "Kubernetes manifest analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "runAsNonRoot: true" in template
        assert "allowPrivilegeEscalation: false" in template

    def test_finding_format(self):
        finding = KubernetesFinding(
            kind="privileged",
            severity="high",
            message="privileged mode",
            path="k8s/deployment.yaml",
            lineno=10,
            resource="Deployment",
        )
        assert "k8s/deployment.yaml:10" in finding.format()
        assert "Deployment" in finding.format()
