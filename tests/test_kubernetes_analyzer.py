"""Tests for KubernetesAnalyzer."""

from pathlib import Path

from devai.kubernetes_analyzer import KubernetesAnalyzer, KubernetesFinding


INSECURE_MANIFEST = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
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
            - name: API_SECRET
              value: supersecret
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: true
          volumeMounts:
            - mountPath: /var/run/docker.sock
              name: docker-sock
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
"""

HARDENED_MANIFEST = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: api
          image: python:3.12-slim
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
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
        assert "runs_as_root" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_manifest_scores_well(self, tmp_path: Path):
        k8s = tmp_path / "kubernetes"
        k8s.mkdir()
        (k8s / "api.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.resources == 1

    def test_finds_nested_manifests(self, tmp_path: Path):
        deploy = tmp_path / "deploy"
        deploy.mkdir()
        manifest = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: worker\n"
            "spec:\n  containers:\n    - name: c\n      image: alpine:3.19\n"
        )
        (deploy / "worker.yaml").write_text(manifest, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert analyzer.stats.manifest_files == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        k8s = tmp_path / "k8s"
        k8s.mkdir()
        (k8s / "app.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        assert "Kubernetes manifests:" in analyzer.summary()
        assert "Kubernetes analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "runAsNonRoot: true" in template
        assert "drop:" in template

    def test_finding_format(self):
        finding = KubernetesFinding(
            kind="privileged",
            severity="high",
            message="test",
            path="k8s/deploy.yaml",
            lineno=10,
            resource="Deployment/web",
        )
        assert "Deployment/web" in finding.format()
