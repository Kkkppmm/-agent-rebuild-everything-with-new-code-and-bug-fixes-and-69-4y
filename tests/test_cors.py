"""Tests for CORSAnalyzer."""

from pathlib import Path

from devai.cors import CORSAnalyzer


SAFE_CODE = '''
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],
    allow_credentials=True,
)
'''

RISKY_CODE = '''
from flask_cors import CORS

CORS(app, origins="*", supports_credentials=True)

ALLOWED_ORIGIN = "*"
'''


class TestCORSAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = CORSAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CORSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CORSAnalyzer(str(tmp_path))
        assert "CORS misconfigurations" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
