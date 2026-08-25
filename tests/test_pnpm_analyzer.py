"""Tests for PnpmAnalyzer."""

from pathlib import Path

from devai.pnpm_analyzer import PnpmAnalyzer, PnpmFinding


INSECURE_PNPM = """\
packages:
  - "apps/*"
  - "packages/*"
  - ".env"
  - ".ssh/id_rsa"

catalog:
  react: latest
"""

INSECURE_NPMRC = """\
//registry.npmjs.org/:_authToken=npm_hardcoded_token_abcdefghijklmnopqrst
registry=http://insecure-registry.example.com
strict-ssl=false
trust-policy=off
shamefully-hoist=true
"""

INSECURE_PNPMFILE = """\
module.exports = {
  hooks: {
    readPackage(pkg) {
      pkg.dependencies['evil'] = 'git+https://user:password@github.com/org/repo.git#main';
      return pkg;
    }
  }
};
"""

HARDENED_PNPM = """\
packages:
  - "apps/*"
  - "packages/*"
"""


class TestPnpmAnalyzer:
    def test_detects_insecure_workspace(self, tmp_path: Path):
        (tmp_path / "pnpm-workspace.yaml").write_text(INSECURE_PNPM, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "sensitive_path" in kinds
        assert "unpinned_catalog" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_insecure_npmrc(self, tmp_path: Path):
        (tmp_path / ".npmrc").write_text(INSECURE_NPMRC, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "npm_token" in kinds
        assert "insecure_http" in kinds
        assert "strict_ssl_off" in kinds
        assert "trust_policy_off" in kinds
        assert "shamefully_hoist" in kinds

    def test_detects_insecure_pnpmfile(self, tmp_path: Path):
        (tmp_path / ".pnpmfile.cjs").write_text(INSECURE_PNPMFILE, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / "pnpm-workspace.yaml").write_text(HARDENED_PNPM, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = PnpmAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = PnpmFinding(
            kind="test",
            severity="high",
            message="test message",
            path="pnpm-workspace.yaml",
            lineno=1,
        )
        assert "[high] pnpm-workspace.yaml:1" in finding.format()

    def test_generate_hardened_config(self):
        config = PnpmAnalyzer(".").generate_hardened_config()
        assert "trust-policy=strict" in config
        assert "strict-ssl=true" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".npmrc").write_text(INSECURE_NPMRC, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "pnpm analysis:" in context
        assert "findings:" in context
