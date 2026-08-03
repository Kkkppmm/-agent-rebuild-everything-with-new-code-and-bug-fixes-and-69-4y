"""Tests for XSSAnalyzer."""

from pathlib import Path

from devai.xss import XSSAnalyzer

SAFE_CODE = '''
from flask import escape, request

def greet():
    name = escape(request.args.get("name", ""))
    return f"<p>Hello {name}</p>"
'''

RISKY_CODE = '''
from flask import request

def greet():
    return f"<div>{request.args.get('name')}</div>"

def unsafe_markup():
    from markupsafe import Markup
    return Markup(request.args.get("html"))
'''


class TestXSSAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = XSSAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_fstring_html(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XSSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "fstring_html" in patterns
        assert analyzer.health_score() < 100.0

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XSSAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XSSAnalyzer(str(tmp_path))
        assert "XSS:" in analyzer.summary()
        assert "XSS analysis:" in analyzer.to_context()
