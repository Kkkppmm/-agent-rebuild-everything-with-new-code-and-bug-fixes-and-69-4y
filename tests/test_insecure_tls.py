"""Tests for InsecureTLSAnalyzer."""

from pathlib import Path

from devai.insecure_tls import InsecureTLSAnalyzer


SAFE_CODE = '''
import requests

def fetch(url):
    return requests.get(url, verify=True)
'''

RISKY_CODE = '''
import requests
import httpx
import ssl

def fetch_insecure(url):
    return requests.get(url, verify=False)

def fetch_httpx(url):
    return httpx.get(url, verify=False)

def make_context():
  return ssl._create_unverified_context()
'''


class TestInsecureTLSAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "verify_false" in patterns
        assert "unverified_ssl_context" in patterns
        assert len(analyzer.critical_findings()) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        assert "Insecure TLS" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
