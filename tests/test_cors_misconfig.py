"""Tests for CORSMisconfigAnalyzer."""

from pathlib import Path

from devai.cors_misconfig import CORSMisconfigAnalyzer


SAFE_CODE = '''
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],
    allow_credentials=True,
)
'''

RISKY_CODE = '''
from fastapi.middleware.cors import CORSMiddleware
from flask_cors import CORS

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)

CORS(app, origins="*")

def set_header(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
'''


class TestCORSMisconfigAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = CORSMisconfigAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CORSMisconfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "wildcard_origin" in patterns
        assert "wildcard_header" in patterns
        assert any(f.severity == "high" for f in findings)
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CORSMisconfigAnalyzer(str(tmp_path))
        assert "CORS misconfigurations" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
