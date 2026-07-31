"""Tests for ResourceLeakAnalyzer."""

from pathlib import Path

from devai.resource_leaks import ResourceLeak, ResourceLeakAnalyzer


SAFE_CODE = '''
def read_config(path):
    with open(path) as f:
        return f.read()

def fetch_url():
    from urllib.request import urlopen
    with urlopen("https://example.com") as resp:
        return resp.read()
'''

LEAKY_CODE = '''
import socket
import subprocess

def read_file(path):
    f = open(path)
    return f.read()

def make_socket():
    s = socket.socket()
    s.connect(("localhost", 8080))
    return s

def run_cmd():
  return subprocess.Popen(["echo", "hi"])
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
        assert "process" in kinds
        assert all(isinstance(f, ResourceLeak) for f in findings)
        assert analyzer.health_score() < 100.0

    def test_by_kind(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(LEAKY_CODE, encoding="utf-8")
        analyzer = ResourceLeakAnalyzer(str(tmp_path))
        files = analyzer.by_kind("file")
        assert any("open" in f.resource for f in files)

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
        assert "open()" in analyzer.to_context()
