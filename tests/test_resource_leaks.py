"""Tests for ResourceLeakAnalyzer."""

from pathlib import Path

from devai.resource_leaks import ResourceLeak, ResourceLeakAnalyzer

SAFE_CODE = '''
from pathlib import Path
import socket
import sqlite3

def read_config(path):
    with open(path) as f:
        return f.read()

def read_bytes(path):
    with Path(path).open("rb") as f:
        return f.read()

def fetch(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        return sock.recv(1024)

def query_db(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT 1").fetchone()
    finally:
        conn.close()
'''

LEAKY_CODE = '''
import socket
import sqlite3

def read_file(path):
    f = open(path)
    return f.read()

def bare_open(path):
    open(path)

def open_socket():
    sock = socket.socket()
    return sock

def db_query(path):
    conn = sqlite3.connect(path)
    return conn.execute("SELECT 1").fetchone()
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
        assert "socket" in kinds
        assert "connection" in kinds
        assert analyzer.health_score() < 100.0

    def test_by_kind(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        files = analyzer.by_kind("file")
        assert any("open" in f.name for f in files)

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 3

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Resource leaks:" in summary
        context = analyzer.to_context()
        assert "Resource leak analysis:" in context
        assert "open" in context

    def test_format_includes_function(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, ResourceLeak)
        assert "read_file" in finding.format() or finding.function

    def test_stats(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        stats = analyzer.stats
        assert stats.total_findings >= 3
        assert stats.files_with_findings == 1
