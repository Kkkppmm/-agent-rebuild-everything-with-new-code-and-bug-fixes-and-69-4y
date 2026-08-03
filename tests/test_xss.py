"""Tests for XSSAnalyzer."""

from pathlib import Path

from devai.xss import XSSAnalyzer


SAFE_CODE = '''
from flask import escape

def greet(name):
    return f"<p>Hello {escape(name)}</p>"
'''

RISKY_CODE = '''
from flask import request
from django.http import HttpResponse
from markupsafe import Markup

def bad_flask():
    return HttpResponse(request.args.get("q"))

def bad_markup():
    return Markup(request.form.get("html"))

def bad_fstring():
    name = request.args.get("name")
    return f"<h1>Hello {name}</h1>"
'''


class TestXSSAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = XSSAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XSSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "HttpResponse_user_content" in patterns or "markup_user_input" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XSSAnalyzer(str(tmp_path))
        assert "XSS risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
