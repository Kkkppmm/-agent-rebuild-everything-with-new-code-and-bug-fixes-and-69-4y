"""Tests for BunAnalyzer."""

from pathlib import Path

from devai.bun_analyzer import BunAnalyzer, BunFinding


INSECURE_BUNFIG = """\
[install]
registry = "http://insecure-registry.example.com"
trustedDependencies = true

[install.scopes]
"@myorg" = { token = "npm_hardcoded_token_abcdefghijklmnopqrst", url = "https://registry.npmjs.org/" }

[install.cache]
tls.verify = false
"""

INSECURE_LOCK = """\
{
  "lockfileVersion": 1,
  "packages": {
    "evil": {
      "version": "1.0.0",
      "resolved": "git+https://user:password@github.com/org/repo.git#main"
    }
  }
}
"""

HARDENED_BUNFIG = """\
[install]
# trustedDependencies = ["esbuild"]

[install.scopes]
# "@myorg" = { token = "$NPM_TOKEN", url = "https://registry.npmjs.org/" }
"""


class TestBunAnalyzer:
    def test_detects_insecure_bunfig(self, tmp_path: Path):
        (tmp_path / "bunfig.toml").write_text(INSECURE_BUNFIG, encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "npm_token" in kinds
        assert "install_scripts" in kinds
        assert "tls_verify_off" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_lock(self, tmp_path: Path):
        (tmp_path / "bun.lock").write_text(INSECURE_LOCK, encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "unpinned_git_ref" in kinds

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / "bunfig.toml").write_text(HARDENED_BUNFIG, encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = BunAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = BunFinding(
            kind="test",
            severity="high",
            message="test message",
            path="bunfig.toml",
            lineno=1,
        )
        assert "[high] bunfig.toml:1" in finding.format()

    def test_generate_hardened_config(self):
        config = BunAnalyzer(".").generate_hardened_config()
        assert "trustedDependencies" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "bunfig.toml").write_text(INSECURE_BUNFIG, encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Bun analysis:" in context
        assert "findings:" in context
