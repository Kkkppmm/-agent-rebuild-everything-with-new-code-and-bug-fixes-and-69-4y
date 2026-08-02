"""Tests for XssVulnerabilityAnalyzer."""

from pathlib import Path

from devai.xss_vulnerabilities import XssVulnerabilityAnalyzer


SAFE_CODE = '''
def render():
  return "<p>hello</p>"
'''

RISKY_CODE = '''
from django.utils.safestring import mark_safe
from flask import request
from markupsafe import Markup

def bad(request):
    return mark_safe(request.GET.get("html"))

def also_bad():
    return Markup(user_input)
'''


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
        patterns = {f.pattern for f in findings}
        assert "mark_safe_call" in patterns
        assert analyzer.health_score() < 100.0

    def test_detects_safe_filter_in_template(self, tmp_path: Path):
        (tmp_path / "page.html").write_text("{{ content|safe }}", encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "jinja_safe_filter" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        assert "XSS vulnerabilities" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
