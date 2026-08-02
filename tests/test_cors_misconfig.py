"""Tests for CorsMisconfigAnalyzer."""

from pathlib import Path

from devai.cors_misconfig import CorsMisconfigAnalyzer

SAFE_CODE = '''
from flask_cors import CORS

CORS(app, origins=["https://example.com"])
'''

RISKY_CODE = '''
from flask_cors import CORS

CORS(app, origins="*")
'''


class TestCorsMisconfigAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_wildcard_origin(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        assert "CORS" in analyzer.summary()
        assert "CORS misconfiguration analysis:" in analyzer.to_context()
