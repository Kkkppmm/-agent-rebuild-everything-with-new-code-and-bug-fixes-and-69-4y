"""Tests for FluxCDAnalyzer."""

from pathlib import Path

from devai.flux_cd_analyzer import FluxCDAnalyzer, FluxCDFinding


INSECURE_CONFIG = """
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: insecure-source
  namespace: flux-system
spec:
  interval: 1m
  url: http://git.example.com/org/app.git
  insecureSkipTLSVerify: true
  secretRef:
    name: git-creds
  verify:
    mode: none
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: app
  namespace: flux-system
spec:
  interval: 5m
  sourceRef:
    kind: GitRepository
    name: insecure-source
  path: ./deploy
  prune: false
  force: true
  disableWait: true
  postBuild:
    substitute:
      API_KEY: "sk-abcdefghijklmnopqrstuvwxyz1234567890"
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: app
  namespace: flux-system
spec:
  interval: 30m
  chart:
    spec:
      chart: app
      version: latest
      sourceRef:
        kind: HelmRepository
        name: charts
  values:
    image:
      tag: latest
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: flux-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: flux
    namespace: flux-system
"""

HARDENED_CONFIG = """
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: app-source
  namespace: flux-system
spec:
  interval: 5m
  url: https://github.com/org/app.git
  ref:
    branch: main
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
  timeout: 5m
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: app
  namespace: flux-system
spec:
  interval: 30m
  chart:
    spec:
      chart: app
      version: "1.2.3"
      sourceRef:
        kind: HelmRepository
        name: app-charts
  values:
    image:
      tag: "1.2.3"
"""


class TestFluxCDAnalyzer:
    def test_no_manifests_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = FluxCDAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        flux_dir = tmp_path / ".flux"
        flux_dir.mkdir()
        (flux_dir / "kustomization.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = FluxCDAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http_source" in kinds
        assert "insecure_skip_tls" in kinds
        assert "force_apply" in kinds
        assert "cluster_admin_rbac" in kinds
        assert "plaintext_token" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        flux_dir = tmp_path / "clusters" / "prod"
        flux_dir.mkdir(parents=True)
        (flux_dir / "app.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = FluxCDAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity in ("high", "critical") for f in findings)
        assert analyzer.stats.manifests == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        flux_dir = tmp_path / ".flux"
        flux_dir.mkdir()
        (flux_dir / "gitrepository.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = FluxCDAnalyzer(str(tmp_path))
        assert "Flux CD" in analyzer.summary()
        assert "Flux CD analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "GitRepository" in template
        assert "prune: true" in template

    def test_finding_format(self):
        finding = FluxCDFinding(
            kind="insecure_http_source",
            severity="high",
            message="insecure HTTP",
            path="gitrepository.yaml",
            lineno=8,
        )
        assert "gitrepository.yaml:8" in finding.format()
