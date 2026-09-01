"""Tests for v6.99.0 CrossplaneAnalyzer integration."""

from pathlib import Path

from devai import DevAI, CrossplaneAnalyzer


INSECURE_PROVIDER = """\
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-aws
spec:
  package: provider-aws
  insecureSkipTLSVerify: true
"""


class TestCrossplaneIntegration:
    def test_devai_facade(self, tmp_path: Path):
        crossplane_dir = tmp_path / "crossplane"
        crossplane_dir.mkdir()
        (crossplane_dir / "provider.yaml").write_text(INSECURE_PROVIDER, encoding="utf-8")

        devai = DevAI.mock()
        analyzer = devai.crossplane(str(tmp_path))
        assert isinstance(analyzer, CrossplaneAnalyzer)
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "skip_tls_verify" in kinds
        assert "unversioned_provider" in kinds

    def test_public_export(self):
        from devai import CrossplaneAnalyzer, CrossplaneFinding, CrossplaneInfo, CrossplaneStats

        assert CrossplaneAnalyzer is not None
        assert CrossplaneFinding is not None
        assert CrossplaneInfo is not None
        assert CrossplaneStats is not None
