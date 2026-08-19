"""Tests for HardcodedConfigAnalyzer."""

from pathlib import Path

from devai.hardcoded_config import HardcodedConfigAnalyzer


SAFE_CODE = '''
import os

API_URL = os.environ.get("API_URL")
DB_HOST = os.environ.get("DB_HOST")
'''

RISKY_CODE = '''
import os

API_URL = "https://api.example.com/v1"
DB_URL = "postgresql://user:pass@10.0.0.5:5432/mydb"
SECRET = os.environ.get("API_KEY", "default-secret-key")
'''


class TestHardcodedConfigAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "hardcoded_url" in patterns
        assert "hardcoded_db_url" in patterns
        assert "env_default_secret" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        assert "Hardcoded config" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
