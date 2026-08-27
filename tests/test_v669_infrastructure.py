"""Tests for v6.69.0 infrastructure analyzers."""

from pathlib import Path

from devai import ArgoCDAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_ARGOCD = """
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: app
  namespace: argocd
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
"""


class TestV669InfrastructureAnalyzers:
    def test_facade_argocd(self, tmp_path: Path):
        argocd_dir = tmp_path / "argocd"
        argocd_dir.mkdir()
        (argocd_dir / "application.yaml").write_text(HARDENED_ARGOCD, encoding="utf-8")
        analyzer = DevAI.mock().argocd(tmp_path)
        assert isinstance(analyzer, ArgoCDAnalyzer)
        assert analyzer.stats.applications == 1

    def test_project_health_includes_argocd_category(self, tmp_path: Path):
        argocd_dir = tmp_path / "argocd"
        argocd_dir.mkdir()
        (argocd_dir / "application.yaml").write_text(HARDENED_ARGOCD, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "argocd" in names
