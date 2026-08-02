"""Tests for InsecureTLSAnalyzer."""

from pathlib import Path

from devai.insecure_tls import InsecureTLSAnalyzer

SAFE_CODE = '''
import httpx

def fetch_data():
    return httpx.get("https://api.example.com", verify=True)
'''

RISKY_CODE = '''
import httpx
import requests

def fetch_insecure(url):
    return requests.get(url, verify=False)

def fetch_no_ssl():
    return httpx.get("https://example.com", ssl=False)
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
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        assert "Insecure TLS" in analyzer.summary()
        assert "Insecure TLS analysis:" in analyzer.to_context()
