"""Tests for ResourceLeakAnalyzer."""

from pathlib import Path

from devai.resource_leaks import ResourceLeakAnalyzer


SAFE_CODE = '''
def read_config(path):
    with open(path) as f:
        return f.read()
'''

LEAKY_CODE = '''
import sqlite3

def read_bad(path):
    f = open(path)
    return f.read()

def connect_bad(db_path):
    conn = sqlite3.connect(db_path)
    return conn
'''


class TestResourceLeakAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_leaks(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        resources = {f.resource for f in findings}
        assert "file" in resources
        assert "connection" in resources
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        assert "Resource leaks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
