"""Tests for K8sAnalyzer."""

from pathlib import Path

from devai.k8s_analyzer import K8sAnalyzer, K8sFinding

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
      hostIPC: true
      automountServiceAccountToken: true
      containers:
        - name: web
          image: nginx:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsUser: 0
            readOnlyRootFilesystem: false
          env:
            - name: API_SECRET
              value: supersecret
          capabilities:
            add:
              - ALL
          volumeMounts:
            - mountPath: /var/run/docker.sock
              name: docker-sock
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
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
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: web
          image: python:3.12-slim
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsUser: 1000
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


class TestK8sAnalyzer:
    def test_no_manifests_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        assert analyzer.stats.manifest_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "host_pid" in kinds
        assert "host_ipc" in kinds
        assert "latest_tag" in kinds
        assert "docker_sock_mount" in kinds
        assert "sensitive_host_path" in kinds
        assert "secret_in_env" in kinds
        assert "cap_add_all" in kinds
        assert "allow_privilege_escalation" in kinds
        assert "run_as_root" in kinds
        assert "writable_root_fs" in kinds
        assert "automount_service_token" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_manifest_scores_well(self, tmp_path: Path):
        (tmp_path / "deployment.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.manifest_files == 1
        assert "Deployment" in analyzer.infos[0].kinds

    def test_finding_format(self):
        finding = K8sFinding(
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
        analyzer = K8sAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "securityContext:" in template
        assert "runAsNonRoot: true" in template
        assert "resources:" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "manifests").mkdir()
        (tmp_path / "manifests" / "app.yml").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Kubernetes Manifest Audit" in context
        assert "privileged" in context.lower() or "high" in context
