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
          env:
            - name: API_SECRET
              value: supersecret
          securityContext:
            privileged: true
            runAsNonRoot: false
            allowPrivilegeEscalation: true
            capabilities:
              add:
                - ALL
          volumeMounts:
            - name: host
              mountPath: /host
      volumes:
        - name: host
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
          image: python:3.12-slim
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
          resources:
            limits:
              cpu: "1"
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
        assert "host_pid" in kinds
        assert "latest_tag" in kinds
        assert "secret_in_env" in kinds
        assert "run_as_non_root_false" in kinds
        assert "allow_privilege_escalation" in kinds
        assert "cap_add_all" in kinds
        assert "host_path_volume" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_manifest_scores_well(self, tmp_path: Path):
        k8s = tmp_path / "kubernetes"
        k8s.mkdir()
        (k8s / "app.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert "Deployment" in analyzer.infos[0].kinds

    def test_finding_format(self):
        finding = KubernetesFinding(
            kind="privileged",
            severity="high",
            message="test",
            path="k8s/deployment.yaml",
            lineno=12,
            resource="app",
        )
        assert "app" in finding.format()
        assert "k8s/deployment.yaml:12" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = KubernetesAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "runAsNonRoot: true" in template
        assert "resources:" in template

    def test_to_context(self, tmp_path: Path):
        k8s = tmp_path / "deploy"
        k8s.mkdir()
        (k8s / "deployment.yaml").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = KubernetesAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Kubernetes Manifest Audit" in context
        assert "privileged" in context.lower() or "high" in context
