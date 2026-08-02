"""Tests for InsecureCookieAnalyzer."""

from pathlib import Path

from devai.insecure_cookies import InsecureCookieAnalyzer


SAFE_CODE = '''
def set_session(response):
    response.set_cookie("session", "abc", secure=True, httponly=True, samesite="Lax")
'''

RISKY_CODE = '''
def bad_cookie(response):
    response.set_cookie("session", "abc")

def partial_cookie(response):
    response.set_cookie("token", "xyz", secure=True)
'''


class TestInsecureCookieAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        assert "Insecure cookies" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
