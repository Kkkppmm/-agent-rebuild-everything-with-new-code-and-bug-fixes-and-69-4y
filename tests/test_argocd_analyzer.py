"""Tests for ArgoCDAnalyzer."""

from pathlib import Path

from devai.argocd_analyzer import ArgoCDAnalyzer, ArgoCDFinding


INSECURE_CONFIG = """
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: insecure-app
  namespace: argocd
spec:
  project: default
  source:
    repoURL: http://git.example.com/org/app.git
    targetRevision: HEAD
    path: deploy
    helm:
      values: |
        apiKey: "sk-abcdefghijklmnopqrstuvwxyz1234567890"
  destination:
    server: "*"
    namespace: "*"
  syncPolicy:
    automated:
      prune: false
      selfHeal: false
      allowEmpty: true
---
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: wide-open
  namespace: argocd
spec:
  sourceNamespaces:
    - "*"
  destinations:
    - namespace: "*"
      server: "*"
  clusterResourceWhitelist:
    - group: "*"
      kind: "*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: argocd-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: argocd-application-controller
    namespace: argocd
"""

HARDENED_CONFIG = """
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: app
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: https://github.com/org/app.git
    targetRevision: v1.2.3
    path: deploy
  destination:
    server: https://kubernetes.default.svc
    namespace: app
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
"""


class TestArgoCDAnalyzer:
    def test_no_applications_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = ArgoCDAnalyzer(str(tmp_path))
        assert analyzer.stats.applications == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        argocd_dir = tmp_path / "argocd"
        argocd_dir.mkdir()
        (argocd_dir / "application.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = ArgoCDAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http_source" in kinds
        assert "wildcard_namespace" in kinds
        assert "wildcard_server" in kinds
        assert "allow_empty_sync" in kinds
        assert "cluster_admin_rbac" in kinds
        assert "plaintext_token" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        apps_dir = tmp_path / "applications"
        apps_dir.mkdir()
        (apps_dir / "app.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = ArgoCDAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity in ("high", "critical") for f in findings)
        assert analyzer.stats.applications == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        argocd_dir = tmp_path / ".argocd"
        argocd_dir.mkdir()
        (argocd_dir / "application.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = ArgoCDAnalyzer(str(tmp_path))
        assert "Argo CD" in analyzer.summary()
        assert "Argo CD analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "Application" in template
        assert "prune: true" in template

    def test_finding_format(self):
        finding = ArgoCDFinding(
            kind="insecure_http_source",
            severity="high",
            message="insecure HTTP",
            path="application.yaml",
            lineno=8,
        )
        assert "application.yaml:8" in finding.format()
