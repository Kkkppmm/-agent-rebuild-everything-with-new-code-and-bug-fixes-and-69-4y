"""Tests for OpenRedirectAnalyzer."""

from pathlib import Path

from devai.open_redirect import OpenRedirectAnalyzer


SAFE_CODE = '''
from flask import redirect

ALLOWED = {"https://app.example.com", "https://docs.example.com"}

def login_success():
    return redirect("https://app.example.com/dashboard")
'''

RISKY_CODE = '''
from flask import redirect, request
from django.http import HttpResponseRedirect
from fastapi.responses import RedirectResponse

def bad_redirect():
    next_url = request.args.get("next")
    return redirect(next_url)

def django_redirect():
    return HttpResponseRedirect(request.GET["return_url"])

def fastapi_redirect(target_url: str):
    return RedirectResponse(url=target_url)
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
        patterns = {f.pattern for f in findings}
        assert "dynamic_redirect_url" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert "Open redirect risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 2
