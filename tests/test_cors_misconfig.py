"""Tests for CorsMisconfigAnalyzer."""

from pathlib import Path

from devai.cors_misconfig import CorsMisconfigAnalyzer


SAFE_CODE = '''
from flask_cors import CORS

def create_app(app):
    CORS(app, origins=["https://example.com"])
'''

RISKY_CODE = '''
from flask_cors import CORS

def create_app(app):
    CORS(app, origins="*")
'''

FASTAPI_RISKY = '''
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"])
'''


class TestCorsMisconfigAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_flask_wildcard(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_detects_fastapi_wildcard(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(FASTAPI_RISKY, encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "fastapi_wildcard" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        assert "CORS misconfigurations" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
