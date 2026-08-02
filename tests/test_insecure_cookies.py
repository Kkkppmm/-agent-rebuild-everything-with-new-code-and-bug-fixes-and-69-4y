"""Tests for InsecureCookieAnalyzer."""

from pathlib import Path

from devai.insecure_cookies import InsecureCookieAnalyzer

SAFE_CODE = '''
def set_session(response):
    response.set_cookie("session", "abc", secure=True, httponly=True, samesite="Lax")
'''

RISKY_CODE = '''
def set_session(response):
    response.set_cookie("session", "abc")
'''


class TestInsecureCookieAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.pattern == "missing_secure" for f in findings)

    def test_detects_missing_flags(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "missing_secure" in patterns
        assert "missing_httponly" in patterns

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        assert "Insecure cookies" in analyzer.summary()
        assert "Insecure cookie analysis:" in analyzer.to_context()
