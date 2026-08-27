"""Tests for v6.68.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, FluxCDAnalyzer
from devai.project_health import ProjectHealth


HARDENED_FLUX = """
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: app-source
  namespace: flux-system
spec:
  interval: 5m
  url: https://github.com/org/app.git
  secretRef:
    name: git-credentials
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: app
  namespace: flux-system
spec:
  interval: 10m
  sourceRef:
    kind: GitRepository
    name: app-source
  path: ./deploy
  prune: true
  wait: true
"""


class TestV668InfrastructureAnalyzers:
    def test_facade_flux_cd(self, tmp_path: Path):
        flux_dir = tmp_path / ".flux"
        flux_dir.mkdir()
        (flux_dir / "kustomization.yaml").write_text(HARDENED_FLUX, encoding="utf-8")
        analyzer = DevAI.mock().flux_cd(tmp_path)
        assert isinstance(analyzer, FluxCDAnalyzer)
        assert analyzer.stats.manifests == 1

    def test_project_health_includes_flux_cd_category(self, tmp_path: Path):
        flux_dir = tmp_path / ".flux"
        flux_dir.mkdir()
        (flux_dir / "kustomization.yaml").write_text(HARDENED_FLUX, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "flux_cd" in names
