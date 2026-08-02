"""Tests for XssVulnerabilityAnalyzer."""

from pathlib import Path

from devai.xss_vulnerabilities import XssVulnerabilityAnalyzer

SAFE_CODE = '''
from django.utils.html import escape

def render(name):
    return escape(name)
'''

RISKY_CODE = '''
from django.utils.safestring import mark_safe

def render_html(user_input):
    return mark_safe(user_input)
'''

RISKY_TEMPLATE = '<div>{{ user_input|safe }}</div>'


class TestXssVulnerabilityAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_mark_safe(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "mark_safe" for f in findings)

    def test_detects_safe_filter_in_template(self, tmp_path: Path):
        (tmp_path / "template.html").write_text(RISKY_TEMPLATE, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "safe_filter" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        assert "XSS" in analyzer.summary()
        assert "XSS analysis:" in analyzer.to_context()
