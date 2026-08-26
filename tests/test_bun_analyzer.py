"""Tests for BunAnalyzer."""

from pathlib import Path

from devai.bun_analyzer import BunAnalyzer, BunFinding


INSECURE_BUNFIG = """\
[install]
registry = "http://insecure-registry.example.com"
ignoreScripts = false
tls = false

[install.scopes]
"@private" = { token = "npm_hardcoded_token_abcdefghijklmnopqrst", url = "https://registry.npmjs.org/" }

trustedDependencies = ["*"]
"""

INSECURE_LOCK = """\
# bun.lock excerpt
"evil" = { version = "git+https://user:pass@github.com/org/pkg.git#main" }
"lodash" = { version = "latest" }
"""

HARDENED_BUNFIG = """\
[install]
registry = "https://registry.npmjs.org/"
exact = true
ignoreScripts = true
"""


class TestBunAnalyzer:
    def test_detects_insecure_bunfig(self, tmp_path: Path):
        (tmp_path / "bunfig.toml").write_text(INSECURE_BUNFIG, encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "insecure_ssl" in kinds or "hardcoded_secret" in kinds
        assert "trust_all" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_lock(self, tmp_path: Path):
        (tmp_path / "bun.lock").write_text(INSECURE_LOCK, encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "unpinned_dependency" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "bunfig.toml").write_text(HARDENED_BUNFIG, encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = BunAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = BunFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="bunfig.toml",
            lineno=2,
        )
        assert "[high] bunfig.toml:2" in finding.format()

    def test_generate_hardened_config(self):
        config = BunAnalyzer(".").generate_hardened_config()
        assert "ignoreScripts" in config
        assert "registry.npmjs.org" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "bunfig.toml").write_text(INSECURE_BUNFIG, encoding="utf-8")
        context = BunAnalyzer(str(tmp_path)).to_context()
        assert "Bun analysis:" in context
