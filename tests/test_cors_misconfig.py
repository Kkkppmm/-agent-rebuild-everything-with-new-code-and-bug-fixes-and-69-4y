"""Tests for CorsMisconfigAnalyzer."""

from pathlib import Path

from devai.cors_misconfig import CorsMisconfigAnalyzer


SAFE_CODE = '''
CORS_ORIGINS = ["https://app.example.com"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://api.example.com"],
)
'''

RISKY_CODE = '''
from flask_cors import CORS

CORS(app, origins="*")

CORS_ALLOWED_ORIGINS = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
)
'''


class TestCorsMisconfigAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_wildcard_origins(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "flask_cors_wildcard" in patterns
        assert "fastapi_cors_wildcard" in patterns
        assert analyzer.health_score() < 100.0

    def test_detects_config_file_wildcard(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text('cors_allowed_origins = "*"\n', encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern in {"config_cors_wildcard", "settings_cors_wildcard"} for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CorsMisconfigAnalyzer(str(tmp_path))
        assert "CORS misconfigurations" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
