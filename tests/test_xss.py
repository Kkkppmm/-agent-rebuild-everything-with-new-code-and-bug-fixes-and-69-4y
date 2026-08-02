"""Tests for XSSAnalyzer."""

from pathlib import Path

from devai.xss import XSSAnalyzer


SAFE_CODE = '''
from flask import render_template

def show_user():
    return render_template("profile.html", name="Alice")
'''

RISKY_CODE = '''
from flask import render_template_string, request
from markupsafe import Markup
from starlette.responses import HTMLResponse

def bad_template():
    return render_template_string(request.args.get("html"))

def bad_markup(user_input):
    return Markup(user_input)

def bad_html(comment):
    return HTMLResponse(f"<p>{comment}</p>")

def bad_fstring(user_name):
    return f"<div>Hello {user_name}</div>"
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
        assert "template_string_user_input" in patterns
        assert "markup_user_input" in patterns
        assert "html_response_user_input" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XSSAnalyzer(str(tmp_path))
        assert "XSS risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XSSAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 2
