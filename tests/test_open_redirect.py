"""Tests for OpenRedirectAnalyzer."""

from pathlib import Path

from devai.open_redirect import OpenRedirectAnalyzer


SAFE_CODE = '''
from flask import redirect

def go_home():
    return redirect("/dashboard")
'''

RISKY_CODE = '''
from flask import redirect
from fastapi.responses import RedirectResponse

def login_redirect(next_url):
    return redirect(next_url)

def callback(redirect_url):
    return RedirectResponse(redirect_url)
'''


class TestOpenRedirectAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert "Open redirect risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
