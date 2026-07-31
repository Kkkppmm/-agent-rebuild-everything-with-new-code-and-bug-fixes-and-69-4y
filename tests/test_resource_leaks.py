"""Tests for ResourceLeakAnalyzer."""

from pathlib import Path

from devai.resource_leaks import ResourceLeak, ResourceLeakAnalyzer

SAFE_CODE = '''
import sqlite3

def read_config(path):
    with open(path) as f:
        return f.read()

def query_db(path):
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT 1").fetchone()

def manual_close(path):
    f = open(path)
    try:
        return f.read()
    finally:
        f.close()
'''

LEAKY_CODE = '''
import sqlite3
import socket
from urllib.request import urlopen

def read_file(path):
    f = open(path)
    return f.read()

def get_db(path):
    conn = sqlite3.connect(path)
    return conn.execute("SELECT 1").fetchone()

def fetch(url):
    response = urlopen(url)
    return response.read()

def listen():
    s = socket.socket()
    s.bind(("localhost", 0))
    return s.getsockname()
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
        kinds = {f.kind for f in findings}
        assert "unclosed_assignment" in kinds
        assert analyzer.health_score() < 100.0

    def test_by_kind(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        assignments = analyzer.by_kind("unclosed_assignment")
        assert len(assignments) >= 3

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert any("conn" in f.name for f in high)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        assert "Resource leaks:" in analyzer.summary()
        assert "Resource leak analysis" in analyzer.to_context()

    def test_format(self):
        finding = ResourceLeak(
            path="app.py",
            name="read_file.f",
            lineno=5,
            kind="unclosed_assignment",
            severity="medium",
            message="assigned resource 'f' is never closed",
        )
        assert "app.py:5" in finding.format()
        assert "unclosed_assignment" in finding.format()
