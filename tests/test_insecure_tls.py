"""Tests for InsecureTLSAnalyzer."""

from pathlib import Path

from devai.insecure_tls import InsecureTLSAnalyzer


SAFE_CODE = '''
import requests

def fetch(url):
    return requests.get(url, verify=True, timeout=10)
'''

RISKY_CODE = '''
import requests
import ssl
import httpx

def fetch_insecure(url):
    return requests.get(url, verify=False)

def fetch_httpx(url):
    return httpx.post(url, verify=False)

def make_context():
    return ssl._create_unverified_context()

def cert_none():
    return ssl.CERT_NONE
'''


class TestInsecureTLSAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_verify_false(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "verify_false" in patterns
        assert "unverified_context" in patterns
        assert "cert_none" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        assert "Insecure TLS" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 1
