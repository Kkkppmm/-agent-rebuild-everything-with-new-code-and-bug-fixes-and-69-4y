"""Tests for CSRFAnalyzer."""

from pathlib import Path

from devai.csrf import CSRFAnalyzer


SAFE_CODE = '''
from flask import Flask
from flask_wtf.csrf import csrf_protect

app = Flask(__name__)

@app.route("/api/data", methods=["GET"])
def get_data():
    return {"ok": True}
'''

RISKY_CODE = '''
from flask import Flask

app = Flask(__name__)

@app.route("/api/delete", methods=["POST"])
def delete_item():
    return {"deleted": True}

@app.route("/api/update", methods=["PUT"])
def update_item():
    return {"updated": True}
'''


class TestCSRFAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = CSRFAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_missing_csrf(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CSRFAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert any(f.pattern == "missing_csrf_protection" for f in findings)
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CSRFAnalyzer(str(tmp_path))
        assert "CSRF risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
