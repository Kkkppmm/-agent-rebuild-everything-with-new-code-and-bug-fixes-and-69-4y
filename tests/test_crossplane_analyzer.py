"""Tests for CrossplaneAnalyzer."""

from pathlib import Path

from devai.crossplane_analyzer import CrossplaneAnalyzer, CrossplaneFinding


INSECURE_CROSSPLANE = """\
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-aws
spec:
  package: http://insecure.example.com/provider-aws
---
apiVersion: aws.upbound.io/v1beta1
kind: ProviderConfig
metadata:
  name: default
spec:
  credentials:
    source: Secret
    secretRef:
      name: aws-creds
  aws:
    credentials:
      secretAccessKey: supersecret123
---
apiVersion: apiextensions.crossplane.io/v1
kind: Composition
metadata:
  name: xbucket.aws.example.com
spec:
  compositeTypeRef:
    apiVersion: example.com/v1alpha1
    kind: XBucket
  resources:
    - name: bucket
      base:
        apiVersion: s3.aws.upbound.io/v1beta1
        kind: Bucket
        spec:
          forProvider:
            deletionPolicy: Delete
            publiclyAccessible: true
      patches:
        - type: FromCompositeFieldPath
          fromFieldPath: spec.region
          toFieldPath: spec.forProvider.region
"""

HARDENED_CROSSPLANE = """\
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-aws
spec:
  package: xpkg.upbound.io/upbound/provider-aws-s3:v1.14.0
  packagePullPolicy: IfNotPresent
---
apiVersion: aws.upbound.io/v1beta1
kind: ProviderConfig
metadata:
  name: default
spec:
  credentials:
    source: IRSA
"""


class TestCrossplaneAnalyzer:
    def test_no_manifests_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CrossplaneAnalyzer(str(tmp_path))
        assert analyzer.stats.manifests == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        crossplane_dir = tmp_path / "crossplane"
        crossplane_dir.mkdir()
        (crossplane_dir / "provider.yaml").write_text(INSECURE_CROSSPLANE, encoding="utf-8")
        analyzer = CrossplaneAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http_source" in kinds
        assert "plaintext_credentials" in kinds
        assert "public_access" in kinds
        assert "deletion_policy_delete" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_template_scores_well(self, tmp_path: Path):
        crossplane_dir = tmp_path / "crossplane"
        crossplane_dir.mkdir()
        (crossplane_dir / "provider.yaml").write_text(HARDENED_CROSSPLANE, encoding="utf-8")
        analyzer = CrossplaneAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.manifests == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        crossplane_dir = tmp_path / "crossplane"
        crossplane_dir.mkdir()
        (crossplane_dir / "provider.yaml").write_text(HARDENED_CROSSPLANE, encoding="utf-8")
        analyzer = CrossplaneAnalyzer(str(tmp_path))
        assert "Crossplane" in analyzer.summary()
        assert "Crossplane manifest analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "xpkg.upbound.io" in template
        assert "IRSA" in template

    def test_finding_format(self):
        finding = CrossplaneFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="provider.yaml",
            lineno=5,
            line="secret: abc123",
        )
        assert "provider.yaml:5" in finding.format()
        assert "test message" in finding.format()
