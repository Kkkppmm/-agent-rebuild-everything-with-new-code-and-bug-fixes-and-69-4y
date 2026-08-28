"""Tests for KustomizeAnalyzer."""

from pathlib import Path

from devai.kustomize_analyzer import KustomizeAnalyzer, KustomizeFinding


INSECURE_KUSTOMIZE = """\
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - http://example.com/manifests/deployment.yaml
  - git::https://github.com/org/infra.git//base?ref=main

bases:
  - git::http://github.com/org/legacy-base.git

secretGenerator:
  - name: app-secrets
    literals:
      - password=supersecret123
      - api_key=sk-live-abc123

images:
  - name: nginx
    newTag: latest

patches:
  - patch: |-
      spec:
        template:
          spec:
            containers:
              - name: app
                securityContext:
                  privileged: true
                  hostNetwork: true

loadRestrictor: LoadRestrictionsNone
disableNameSuffixHash: true
"""

HARDENED_KUSTOMIZE = """\
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: production

resources:
  - ../../base

images:
  - name: ghcr.io/org/app
    newTag: v2.1.0

patches:
  - patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: app
      spec:
        template:
          spec:
            securityContext:
              runAsNonRoot: true
            containers:
              - name: app
                securityContext:
                  allowPrivilegeEscalation: false
    target:
      kind: Deployment
      name: app
"""


class TestKustomizeAnalyzer:
    def test_no_overlays_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = KustomizeAnalyzer(str(tmp_path))
        assert analyzer.stats.overlays == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        overlay = tmp_path / "overlays" / "prod"
        overlay.mkdir(parents=True)
        (overlay / "kustomization.yaml").write_text(INSECURE_KUSTOMIZE, encoding="utf-8")
        analyzer = KustomizeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "secret_literal" in kinds
        assert "insecure_http_source" in kinds or "insecure_remote_resource" in kinds
        assert "load_restrictor_disabled" in kinds
        assert "privileged_patch" in kinds
        assert "latest_image_tag" in kinds
        assert analyzer.stats.overlays == 1
        assert analyzer.stats.high_severity > 0

    def test_hardened_overlay_scores_well(self, tmp_path: Path):
        overlay = tmp_path / "overlays" / "prod"
        overlay.mkdir(parents=True)
        (overlay / "kustomization.yaml").write_text(HARDENED_KUSTOMIZE, encoding="utf-8")
        analyzer = KustomizeAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 90.0
        assert analyzer.stats.findings == 0

    def test_finding_format(self):
        finding = KustomizeFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="kustomization.yaml",
            lineno=10,
            line="password: secret",
        )
        assert "kustomization.yaml:10" in finding.format()

    def test_generate_hardened_overlay(self):
        analyzer = KustomizeAnalyzer(".")
        template = analyzer.generate_hardened_overlay()
        assert "kustomize.config.k8s.io" in template
        assert "runAsNonRoot: true" in template

    def test_to_context(self, tmp_path: Path):
        overlay = tmp_path / "kustomization.yaml"
        overlay.write_text(HARDENED_KUSTOMIZE, encoding="utf-8")
        analyzer = KustomizeAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Kustomize analysis:" in context
        assert "health score" in context

    def test_summary(self, tmp_path: Path):
        overlay = tmp_path / "kustomization.yaml"
        overlay.write_text(HARDENED_KUSTOMIZE, encoding="utf-8")
        analyzer = KustomizeAnalyzer(str(tmp_path))
        assert "1 overlay" in analyzer.summary()
