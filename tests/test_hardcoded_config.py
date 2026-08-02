"""Tests for HardcodedConfigAnalyzer."""

from pathlib import Path

from devai.hardcoded_config import HardcodedConfigAnalyzer

CLEAN_CODE = '''
import os

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
DATABASE_URL = os.getenv("DATABASE_URL")

DOCS = "https://docs.python.org/3/library/os.html"
'''

RISKY_CODE = '''
import os

API_URL = "https://api.prod.example-corp.com/v2"
DB = "postgres://admin:secret@192.168.1.50:5432/mydb"
CACHE = "redis://10.0.0.12:6379/0"

def get_key():
    return os.environ["API_KEY"]
'''


class TestHardcodedConfigAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(CLEAN_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "hardcoded_url" in patterns
        assert "hardcoded_db_url" in patterns
        assert "hardcoded_ip" in patterns
        assert "env_bracket_access" in patterns
        assert analyzer.health_score() < 100.0

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 1

    def test_by_pattern(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        urls = analyzer.by_pattern("hardcoded_url")
        assert len(urls) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        assert "Hardcoded config" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_skips_test_files(self, tmp_path: Path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HardcodedConfigAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
