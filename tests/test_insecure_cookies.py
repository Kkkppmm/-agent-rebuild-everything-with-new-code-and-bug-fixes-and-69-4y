"""Tests for InsecureCookieAnalyzer."""

from pathlib import Path

from devai.insecure_cookies import InsecureCookieAnalyzer


SAFE_CODE = '''
def set_session(response):
    response.set_cookie("sid", "abc", secure=True, httponly=True, samesite="Lax")
'''

RISKY_CODE = '''
def login(response):
    response.set_cookie("session", token)
    response.set_signed_cookie("auth", value)
'''


class TestInsecureCookieAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_missing_flags(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "missing_secure" in patterns
        assert "missing_httponly" in patterns
        assert "missing_samesite" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        assert "Insecure cookies" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
