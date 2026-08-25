"""Tests for JustfileAnalyzer."""

from pathlib import Path

from devai.justfile_analyzer import JustfileAnalyzer, JustfileFinding


INSECURE_JUSTFILE = """\
set dotenv-load

export API_KEY := "hardcoded-secret-token-12345"
export DATABASE_PASSWORD := "supersecret"

default:
    @just --list

setup:
    curl https://example.com/install.sh | bash
    sudo apt-get install -y build-essential

deploy:
    rm -rf /
    chmod 777 /var/www
    git push origin main --force
    wget http://insecure.example.com/deploy.sh | sh

clone:
    git clone https://user:password@github.com/org/repo.git
"""

HARDENED_JUSTFILE = """\
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

export NODE_ENV := "development"

default:
    @just --list

setup:
    npm ci

test:
    npm test
"""


class TestJustfileAnalyzer:
    def test_detects_insecure_justfile(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(INSECURE_JUSTFILE, encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "export_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_usage" in kinds
        assert "destructive_rm" in kinds
        assert "chmod_777" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "dotenv_load" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(HARDENED_JUSTFILE, encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = JustfileAnalyzer(str(tmp_path))
        assert analyzer.stats.justfiles == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = JustfileFinding(
            kind="test",
            severity="high",
            message="test message",
            path="justfile",
            lineno=1,
        )
        assert "[high] justfile:1" in finding.format()

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(INSECURE_JUSTFILE, encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Justfile analysis:" in context
        assert "piping curl/wget to shell" in context

    def test_generate_hardened_config(self):
        analyzer = JustfileAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "set shell" in config
        assert "npm ci" in config
