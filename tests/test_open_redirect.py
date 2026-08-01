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
from django.shortcuts import redirect as django_redirect

def login_next(request):
    next_url = request.args.get("next")
    return redirect(next_url)

def oauth_callback(callback_url):
    return django_redirect(callback_url)
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
        assert "dynamic_redirect" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert "Open redirect risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 1
