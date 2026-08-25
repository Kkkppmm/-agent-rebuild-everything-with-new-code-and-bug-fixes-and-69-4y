"""Tests for PnpmAnalyzer."""

from pathlib import Path

from devai.pnpm_analyzer import PnpmAnalyzer, PnpmFinding


INSECURE_PNPM = """\
packages:
  - 'packages/*'
  - '.ssh/*'

# .npmrc merged content
registry=http://insecure-registry.example.com
strict-ssl=false
//registry.npmjs.org/:_authToken=npm_hardcoded_token_abcdefghijklmnopqrst
shamefully-hoist=true
ignore-scripts=false
"""

INSECURE_PNPMFILE = """\
module.exports = {
  hooks: {
    readPackage(pkg) {
      pkg.dependencies.evil = "git+https://user:pass@github.com/org/pkg.git#main";
      return pkg;
    }
  }
};
"""

HARDENED_PNPM = """\
packages:
  - 'packages/*'
  - 'apps/*'

strict-peer-dependencies=true
auto-install-peers=false
ignore-scripts=true
registry=https://registry.npmjs.org/
"""


class TestPnpmAnalyzer:
    def test_detects_insecure_pnpm_workspace(self, tmp_path: Path):
        (tmp_path / "pnpm-workspace.yaml").write_text(INSECURE_PNPM, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "insecure_ssl" in kinds or "hardcoded_token" in kinds
        assert analyzer.health_score() < 60.0

    def test_detects_insecure_pnpmfile(self, tmp_path: Path):
        (tmp_path / ".pnpmfile.cjs").write_text(INSECURE_PNPMFILE, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "unpinned_dependency" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "pnpm-workspace.yaml").write_text(HARDENED_PNPM, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = PnpmAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.configs == 0

    def test_finding_format(self):
        finding = PnpmFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="pnpm-workspace.yaml",
            lineno=1,
        )
        assert "[high] pnpm-workspace.yaml:1" in finding.format()

    def test_generate_hardened_config(self):
        config = PnpmAnalyzer(".").generate_hardened_config()
        assert "strict-peer-dependencies" in config
        assert "ignore-scripts" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pnpm-workspace.yaml").write_text(INSECURE_PNPM, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Pnpm analysis:" in context
        assert "findings:" in context
