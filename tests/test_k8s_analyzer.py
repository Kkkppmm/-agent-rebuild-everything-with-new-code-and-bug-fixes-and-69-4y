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
    metadata:
      labels:
        app: app
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
        - name: web
          image: nginx:latest
          privileged: true
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: true
            readOnlyRootFilesystem: false
          env:
            - name: API_SECRET
              value: supersecretkey12345
          volumeMounts:
            - name: docker-sock
              mountPath: /var/run/docker.sock
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
        - name: host-root
          hostPath:
            path: /
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
spec:
  rules:
    - host: "*"
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
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


class TestK8sAnalyzer:
    def test_no_manifests_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 0
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
        assert "run_as_root" in kinds
        assert "privilege_escalation" in kinds
        assert "writable_rootfs" in kinds
        assert "secret_in_environment" in kinds
        assert "docker_sock_mount" in kinds
        assert "wildcard_ingress" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_manifest_scores_well(self, tmp_path: Path):
        k8s_dir = tmp_path / "kubernetes"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.manifests == 1
        assert "Deployment/app" in analyzer.infos[0].resources

    def test_finding_format(self):
        finding = K8sFinding(
            kind="privileged",
            severity="high",
            message="test",
            path="k8s/deployment.yaml",
            lineno=5,
            resource="Deployment/app",
        )
        assert "Deployment/app" in finding.format()
        assert "k8s/deployment.yaml:5" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = K8sAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "runAsNonRoot: true" in template
        assert "resources:" in template
        assert "allowPrivilegeEscalation: false" in template

    def test_to_context(self, tmp_path: Path):
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yaml").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Kubernetes Manifest Audit" in context
        assert "privileged" in context.lower() or "high" in context

    def test_detects_by_content_heuristic(self, tmp_path: Path):
        (tmp_path / "my-app-manifest.yaml").write_text(HARDENED_MANIFEST, encoding="utf-8")
        analyzer = K8sAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 1
