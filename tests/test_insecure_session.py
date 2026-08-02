"""Tests for InsecureSessionAnalyzer."""

from pathlib import Path

from devai.insecure_session import InsecureSessionAnalyzer


SAFE_CODE = '''
import os

SECRET_KEY = os.environ["SECRET_KEY"]
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
'''

RISKY_CODE = '''
SECRET_KEY = "hardcoded-flask-secret-key-value"
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False

def set_session(response):
    response.set_cookie("session", "abc", secure=False, httponly=False)
'''


class TestInsecureSessionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = InsecureSessionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureSessionAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "hardcoded_secret_key" in patterns
        assert "cookie_not_secure" in patterns
        assert "cookie_not_httponly" in patterns
        assert "response_cookie_not_secure" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureSessionAnalyzer(str(tmp_path))
        assert "Insecure session" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureSessionAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 3
