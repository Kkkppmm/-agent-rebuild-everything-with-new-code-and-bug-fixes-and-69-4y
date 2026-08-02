"""Tests for InsecureTLSAnalyzer."""

from pathlib import Path

from devai.insecure_tls import InsecureTLSAnalyzer


SAFE_CODE = '''
import httpx

def fetch(url: str):
    return httpx.get(url, verify=True)
'''

RISKY_CODE = '''
import requests
import ssl
import urllib3

def fetch(url):
    requests.get(url, verify=False)
    httpx.get(url, verify=False)
    ssl._create_unverified_context()
    urllib3.disable_warnings()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
'''

CONFIG_RISKY = "verify = False\nssl = False\n"


class TestInsecureTLSAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_verify_false(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "verify_false" in patterns
        assert "unverified_context" in patterns
        assert "cert_none" in patterns
        assert analyzer.health_score() < 100.0

    def test_detects_config_file(self, tmp_path: Path):
        (tmp_path / ".env").write_text(CONFIG_RISKY, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "verify_false" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureTLSAnalyzer(str(tmp_path))
        assert "Insecure TLS:" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
