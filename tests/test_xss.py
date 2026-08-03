"""Tests for XSSAnalyzer."""

from pathlib import Path

from devai.xss import XSSAnalyzer


SAFE_CODE = '''
from flask import render_template

def show_user(uid):
    return render_template("user.html", uid=uid)
'''

RISKY_CODE = '''
from flask import render_template_string
from markupsafe import Markup
from fastapi.responses import HTMLResponse

def show_comment(user_comment):
    return render_template_string(f"<p>{user_comment}</p>")

def raw_html(user_input):
    return Markup(user_input)

def page(content):
    return HTMLResponse(content)
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
        assert "unescaped_html_output" in patterns or "markup_user_input" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XSSAnalyzer(str(tmp_path))
        assert "XSS risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
