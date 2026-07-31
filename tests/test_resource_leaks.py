"""Tests for ResourceLeakAnalyzer."""

from pathlib import Path

from devai.resource_leaks import ResourceLeak, ResourceLeakAnalyzer


SAFE_CODE = '''
def read_config(path):
    with open(path) as f:
        return f.read()

def query_db(path):
    import sqlite3
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT 1").fetchone()
'''

LEAKY_CODE = '''
import socket
import sqlite3

def read_file(path):
    f = open(path)
    return f.read()

def connect_db(path):
  return sqlite3.connect(path)

def make_socket():
    s = socket.socket()
    return s
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
        assert "file" in kinds
        assert "database" in kinds
        assert "socket" in kinds
        assert analyzer.health_score() < 100.0

    def test_by_kind(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        files = analyzer.by_kind("file")
        assert len(files) >= 1

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        assert "Resource leaks" in analyzer.summary()
        assert "Resource leak analysis" in analyzer.to_context()

    def test_finding_format(self):
        leak = ResourceLeak(
            path="app.py",
            resource="open",
            lineno=4,
            kind="file",
            severity="high",
            message="use with",
            function="read_file",
        )
        assert "app.py:4" in leak.format()
        assert "read_file()" in leak.format()
