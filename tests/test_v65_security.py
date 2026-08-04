"""Tests for v6.5.0 security analyzers."""

from pathlib import Path

from devai import (
    ClickjackingAnalyzer,
    HostHeaderAnalyzer,
    SecurityScanner,
    SessionFixationAnalyzer,
)


CLICKJACKING_SAFE = '''
from flask import Flask, make_response

app = Flask(__name__)

@app.route("/")
def index():
    resp = make_response("ok")
    resp.headers["X-Frame-Options"] = "DENY"
    return resp
'''

CLICKJACKING_RISKY = '''
from flask import render_template

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")
'''

HOST_HEADER_SAFE = '''
def home():
    return redirect("/welcome")
'''

HOST_HEADER_RISKY = '''
from flask import redirect, request

def reset_password():
    return redirect(f"https://{request.host}/reset")
'''

SESSION_FIXATION_SAFE = '''
def login(user):
    session.clear()
    session["user_id"] = user.id
'''

SESSION_FIXATION_RISKY = '''
def login(request):
    sid = request.args.get("sessionid")
    session["sid"] = sid
'''


class TestClickjackingAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(CLICKJACKING_SAFE, encoding="utf-8")
        analyzer = ClickjackingAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_missing_protection(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(CLICKJACKING_RISKY, encoding="utf-8")
        analyzer = ClickjackingAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "missing_frame_protection" for f in findings)
        assert analyzer.health_score() < 100.0


class TestHostHeaderAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "routes.py").write_text(HOST_HEADER_SAFE, encoding="utf-8")
        analyzer = HostHeaderAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []

    def test_detects_host_in_redirect(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(HOST_HEADER_RISKY, encoding="utf-8")
        analyzer = HostHeaderAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "host_in_fstring" in patterns
        assert "host_in_redirect" in patterns


class TestSessionFixationAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(SESSION_FIXATION_SAFE, encoding="utf-8")
        analyzer = SessionFixationAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []

    def test_detects_session_id_in_url(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(SESSION_FIXATION_RISKY, encoding="utf-8")
        analyzer = SessionFixationAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "session_id_in_url" for f in findings)

    def test_detects_missing_regeneration(self, tmp_path: Path):
        code = '''
def user_login(credentials):
  session["user"] = credentials.username
'''
        (tmp_path / "auth.py").write_text(code, encoding="utf-8")
        analyzer = SessionFixationAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "missing_session_regeneration" for f in findings)


class TestSecurityScannerV65:
    def test_includes_new_checks(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def ok(): return 1\n", encoding="utf-8")
        scanner = SecurityScanner(str(tmp_path))
        report = scanner.scan()
        names = {cat.name for cat in report.categories}
        assert "clickjacking" in names
        assert "host_header" in names
        assert "session_fixation" in names
        assert len(report.categories) >= 32

    def test_recommendations_for_new_checks(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(CLICKJACKING_RISKY, encoding="utf-8")
        (tmp_path / "auth.py").write_text(HOST_HEADER_RISKY + "\n" + SESSION_FIXATION_RISKY, encoding="utf-8")
        scanner = SecurityScanner(
            str(tmp_path),
            checks=("clickjacking", "host_header", "session_fixation"),
        )
        report = scanner.scan()
        joined = " ".join(report.recommendations)
        assert "X-Frame-Options" in joined
        assert "Host header" in joined
        assert "session" in joined.lower()
