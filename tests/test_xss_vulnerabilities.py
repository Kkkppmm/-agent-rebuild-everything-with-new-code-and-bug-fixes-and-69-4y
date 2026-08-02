"""Tests for XssVulnerabilityAnalyzer."""

from pathlib import Path

from devai.xss_vulnerabilities import XssVulnerabilityAnalyzer


SAFE_CODE = '''
def render(name):
    return f"<p>{name}</p>"
'''

RISKY_CODE = '''
from django.utils.safestring import mark_safe
from jinja2 import Environment

def render(user_html):
    return mark_safe(user_html)

env = Environment(autoescape=False)
'''


class TestXssVulnerabilityAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "mark_safe" in patterns
        assert "jinja_autoescape_disabled" in patterns
        assert analyzer.health_score() < 100.0

    def test_template_files(self, tmp_path: Path):
        (tmp_path / "template.html").write_text("{{ user_input|safe }}", encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "template_safe_filter" for f in findings)
