"""Tests for OpenRedirectAnalyzer."""

from pathlib import Path

from devai.open_redirect import OpenRedirectAnalyzer

SAFE_CODE = '''
from flask import redirect, url_for

def login():
    return redirect(url_for("dashboard"))

def logout():
    return redirect("/login")
'''

RISKY_CODE = '''
from flask import redirect, request
from django.http import HttpResponseRedirect
from fastapi.responses import RedirectResponse

def flask_redirect():
    next_url = request.args.get("next")
    return redirect(next_url)

def django_redirect(request):
    return HttpResponseRedirect(request.GET.get("return"))

def fastapi_redirect(url: str):
    return RedirectResponse(url=request.query_params.get("redirect"))
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

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert "Open redirect" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
