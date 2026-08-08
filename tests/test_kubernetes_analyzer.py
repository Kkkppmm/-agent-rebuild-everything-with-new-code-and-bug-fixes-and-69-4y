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
      hostPID: true
      containers:
        - name: app
          image: myapp:latest
          securityContext:
            privileged: true
            runAsNonRoot: false
            allowPrivilegeEscalation: true
            readOnlyRootFilesystem: false
          env:
            - name: API_KEY
              value: supersecret
          resources:
            requests:
              cpu: 100m
          volumeMounts:
            - name: host-root
              mountPath: /data
      volumes:
        - name: host-root
          hostPath:
            path: /
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
          image: myregistry/app:1.0.0
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
    def test_no_manifests_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 0
        assert analyzer.health_score() == 100.0
        assert "no manifests found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "host_pid" in kinds
        assert "run_as_root" in kinds
        assert "privilege_escalation" in kinds
        assert "latest_tag" in kinds
        assert "secret_in_env" in kinds
        assert "host_path_root" in kinds
        assert analyzer.health_score() < 30.0

    def test_hardened_manifest_scores_well(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.manifests == 1
        assert "Deployment" in analyzer.infos[0].kinds

    def test_generate_template(self):
        template = KubernetesAnalyzer(".").generate_hardened_template()
        assert "kind: Deployment" in template
        assert "runAsNonRoot: true" in template
        assert "limits:" in template

    def test_to_context(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(INSECURE_MANIFEST, encoding="utf-8")
        ctx = KubernetesAnalyzer(str(tmp_path)).to_context()
        assert "Kubernetes manifest analysis" in ctx
        assert "health score" in ctx

    def test_ignores_non_k8s_yaml(self, tmp_path: Path):
        (tmp_path / "docker-compose.yaml").write_text(
            "version: '3'\nservices:\n  app:\n    image: app:latest\n",
            encoding="utf-8",
        )
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 0
