"""Tests for CSRFAnalyzer."""

from pathlib import Path

from devai.csrf import CSRFAnalyzer


SAFE_CODE = '''
from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
CSRFProtect(app)

@app.route("/login", methods=["GET"])
def login_form():
    return "form"

@app.route("/submit", methods=["POST"])
@csrf_protect
def submit():
    return "ok"
'''

RISKY_CODE = '''
from flask import Flask, request
from fastapi import FastAPI

app = Flask(__name__)
api = FastAPI()

@app.route("/submit", methods=["POST"])
def submit():
    return request.form["data"]

@api.post("/users")
async def create_user():
    return {"created": True}

@app.route("/update", methods=["PUT", "PATCH"])
def update():
    return "updated"
'''

PROTECTED_MODULE = '''
from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
CSRFProtect(app)

@app.route("/submit", methods=["POST"])
def submit():
    return "ok"
'''


class TestCSRFAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = CSRFAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CSRFAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "unprotected_post_handler" in patterns or "missing_csrf_protection" in patterns
        assert len(findings) >= 2
        assert analyzer.health_score() < 100.0

    def test_module_level_protection(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(PROTECTED_MODULE, encoding="utf-8")
        analyzer = CSRFAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CSRFAnalyzer(str(tmp_path))
        assert "CSRF risks:" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
