"""Tests for HardcodedConfigAnalyzer."""

from pathlib import Path

from devai.hardcoded_config import HardcodedConfigAnalyzer


SAFE_CODE = '''
import os

DATABASE_URL = os.getenv("DATABASE_URL")
API_HOST = os.environ["API_HOST"]
'''

RISKY_CODE = '''
import os

API_URL = "https://api.mycompany.io/v1"
DB_URL = "postgresql://user:pass@db.internal:5432/app"
HOST = "203.0.113.50"
TIMEOUT = os.getenv("TIMEOUT", "30")
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
        assert "database_url" in patterns
        assert "hardcoded_ip" in patterns
        assert "env_default" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        assert "Hardcoded configuration" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity_db_url(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            'CONN = "mysql://admin:secret@10.0.0.5/prod"\n',
            encoding="utf-8",
        )
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        assert analyzer.high_severity()
