"""Tests for XssVulnerabilityAnalyzer."""

from pathlib import Path

from devai.xss_vulnerabilities import XssVulnerabilityAnalyzer


SAFE_CODE = '''
def render(content):
    return content
'''

RISKY_CODE = '''
from django.utils.safestring import mark_safe

def render(user_html):
    return mark_safe(user_html)
'''

TEMPLATE_RISKY = "<div>{{ user_input | safe }}</div>"


class TestXssVulnerabilityAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_mark_safe(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "mark_safe" for f in findings)
        assert analyzer.health_score() < 100.0

    def test_detects_template_safe_filter(self, tmp_path: Path):
        (tmp_path / "template.html").write_text(TEMPLATE_RISKY, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "template_safe_filter" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XssVulnerabilityAnalyzer(str(tmp_path))
        assert "XSS vulnerabilities" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
