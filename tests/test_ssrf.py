"""Tests for SSRFAnalyzer."""

from pathlib import Path

from devai.ssrf import SSRFAnalyzer

SAFE_CODE = '''
import httpx

API_BASE = "https://api.example.com"

def fetch_user(user_id: str):
    return httpx.get(f"{API_BASE}/users/{user_id}")
'''

RISKY_CODE = '''
import requests
import httpx

def fetch_url(user_url: str):
    return requests.get(user_url)

def proxy_request(target_url):
    return httpx.get(url=target_url)
'''


class TestSSRFAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = SSRFAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_dynamic_urls(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SSRFAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "dynamic_url" in patterns or "dynamic_url_kwarg" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SSRFAnalyzer(str(tmp_path))
        assert "SSRF" in analyzer.summary()
        assert "SSRF analysis:" in analyzer.to_context()
