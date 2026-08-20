"""Tests for OpenRedirectAnalyzer."""

from pathlib import Path

from devai.open_redirect import OpenRedirectAnalyzer


SAFE_CODE = '''
from flask import redirect

def login():
    return redirect("/dashboard")
'''

RISKY_CODE = '''
from flask import redirect, request
from starlette.responses import RedirectResponse

def bad_flask():
    return redirect(request.args.get("next"))

def bad_starlette():
    return RedirectResponse(request.query_params.get("url"))

def bad_param(next):
    return redirect(next)
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
        assert "redirect_user_url" in patterns
        assert "RedirectResponse_user_url" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert "Open redirect" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
