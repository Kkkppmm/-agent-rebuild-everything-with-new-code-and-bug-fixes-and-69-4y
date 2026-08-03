"""Tests for HardcodedConfigAnalyzer."""

from pathlib import Path

from devai.hardcoded_config import HardcodedConfigAnalyzer


SAFE_CODE = '''
import os

DATABASE_URL = os.environ.get("DATABASE_URL")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
'''

RISKY_CODE = '''
DATABASE_URL = "postgresql://user:pass@localhost/mydb"
ADMIN_PASSWORD = "supersecret123"
DEBUG = True
API_URL = "https://api.example.com/v1"
'''


class TestHardcodedConfigAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "hardcoded_database_url" in patterns
        assert "hardcoded_admin_password" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        assert "Hardcoded config" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
