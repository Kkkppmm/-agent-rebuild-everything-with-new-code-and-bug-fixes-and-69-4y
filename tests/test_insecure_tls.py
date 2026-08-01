"""Tests for InsecureTLSAnalyzer."""

from pathlib import Path

from devai.insecure_tls import InsecureTLSAnalyzer


SAFE_CODE = '''
import requests

def fetch(url):
    return requests.get(url)
'''

RISKY_CODE = '''
import requests
import httpx
import ssl

def bad_requests(url):
    return requests.get(url, verify=False)

def bad_httpx(url):
    return httpx.get(url, verify=False)

def bad_ssl():
  ctx = ssl._create_unverified_context()
  return ssl.CERT_NONE
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
        assert "requests_verify_false" in patterns
        assert "httpx_verify_false" in patterns
        assert "ssl__create_unverified_context" in patterns
        assert "ssl_CERT_NONE" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        assert "Insecure TLS" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
