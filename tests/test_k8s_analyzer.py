"""Tests for K8sManifestAnalyzer."""

from pathlib import Path

from devai.k8s_analyzer import K8sFinding, K8sManifestAnalyzer

INSECURE_MANIFEST = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
        - name: app
          image: nginx:latest
          privileged: true
          securityContext:
            runAsUser: 0
            runAsNonRoot: false
            allowPrivilegeEscalation: true
            capabilities:
              add:
                - ALL
          env:
            - name: API_SECRET
              value: supersecret
          volumeMounts:
            - name: docker-sock
              mountPath: /var/run/docker.sock
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
---
apiVersion: v1
kind: Service
metadata:
  name: insecure-svc
spec:
  type: LoadBalancer
  ports:
    - port: 80
"""

HARDENED_MANIFEST = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: app
          image: python:3.12-slim
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: "1"
              memory: 512Mi
          env:
            - name: APP_ENV
              value: production
"""


class TestK8sManifestAnalyzer:
    def test_no_manifests_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = K8sManifestAnalyzer(str(tmp_path))
        assert analyzer.stats.manifest_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = K8sManifestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "privileged" in kinds
        assert "host_network" in kinds
        assert "host_pid" in kinds
        assert "host_ipc" in kinds
        assert "latest_tag" in kinds
        assert "run_as_root" in kinds
        assert "run_as_non_root_false" in kinds
        assert "privilege_escalation" in kinds
        assert "cap_add_all" in kinds
        assert "secret_in_env" in kinds
        assert "docker_sock_hostpath" in kinds
        assert "load_balancer" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_manifest_scores_well(self, tmp_path: Path):
        (tmp_path / "deploy.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = K8sManifestAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.manifest_files == 1
        assert "secure-app" in analyzer.infos[0].resources
        assert analyzer.health_score() >= 90.0

    def test_finding_format(self):
        finding = K8sFinding(
            kind="privileged",
            severity="high",
            message="privileged pod",
            path="k8s/deployment.yaml",
            lineno=12,
            resource="insecure-app",
        )
        assert "k8s/deployment.yaml:12" in finding.format()
        assert "insecure-app" in finding.format()

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "manifest.yml").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = K8sManifestAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Kubernetes Manifest Audit" in context
        assert "privileged" in context.lower()

    def test_generate_hardened_template(self):
        template = K8sManifestAnalyzer(".").generate_hardened_template()
        assert "runAsNonRoot: true" in template
        assert "readOnlyRootFilesystem: true" in template
