"""Tests for ClickjackingAnalyzer."""

from pathlib import Path

from devai.clickjacking import ClickjackingAnalyzer


SAFE_CODE = '''
from fastapi.responses import HTMLResponse

def page():
    resp = HTMLResponse("<html></html>")
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return resp
'''

RISKY_CODE = '''
from flask import render_template

@app.route("/")
def home():
    return render_template("index.html")
'''


class TestClickjackingAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = ClickjackingAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = ClickjackingAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "missing_frame_protection" for f in findings)
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = ClickjackingAnalyzer(str(tmp_path))
        assert "Clickjacking" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
