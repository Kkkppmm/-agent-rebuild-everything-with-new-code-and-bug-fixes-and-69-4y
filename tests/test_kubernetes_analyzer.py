"""Tests for KubernetesAnalyzer."""

from pathlib import Path

from devai.kubernetes_analyzer import KubernetesAnalyzer


INSECURE_MANIFEST = """
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
            - name: API_SECRET
              value: supersecret
          volumeMounts:
            - mountPath: /data
      volumes:
        - name: data
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
          image: ghcr.io/org/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
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
    def test_no_manifests_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "latest_tag" in kinds
        assert "run_as_root" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_manifest_scores_well(self, tmp_path: Path):
        k8s = tmp_path / "kubernetes"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.manifests == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        k8s = tmp_path / "deploy"
        k8s.mkdir()
        (k8s / "app.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert "Kubernetes manifests:" in analyzer.summary()
        assert "Kubernetes manifest analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "runAsNonRoot: true" in template
