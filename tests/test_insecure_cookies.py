"""Tests for InsecureCookieAnalyzer."""

from pathlib import Path

from devai.insecure_cookies import InsecureCookieAnalyzer


SAFE_CODE = '''
from flask import Flask, make_response

app = Flask(__name__)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

@app.route("/login")
def login():
    resp = make_response("ok")
    resp.set_cookie("token", "abc", secure=True, httponly=True, samesite="Lax")
    return resp
'''

RISKY_CODE = '''
from flask import Flask, make_response

app = Flask(__name__)
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False

@app.route("/login")
def login():
    resp = make_response("ok")
    resp.set_cookie("token", "abc", secure=False, httponly=False)
    return resp
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
        patterns = {f.pattern for f in findings}
        assert "cookie_missing_secure" in patterns
        assert "cookie_missing_httponly" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        assert "Insecure cookies" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureCookieAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 1
