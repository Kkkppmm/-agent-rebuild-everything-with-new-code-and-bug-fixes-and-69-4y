"""Tests for SSRFAnalyzer."""

from pathlib import Path

from devai.ssrf import SSRFAnalyzer


SAFE_CODE = '''
import requests

API_BASE = "https://api.example.com"

def fetch_user(uid: int):
    return requests.get(f"{API_BASE}/users/{uid}")
'''

RISKY_CODE = '''
import requests
import httpx
import aiohttp
from urllib.request import urlopen

def fetch_url(user_url):
    return requests.get(user_url)

def fetch_httpx(target_url):
    return httpx.post(target_url, json={})

async def fetch_aiohttp(callback_url):
    async with aiohttp.ClientSession() as session:
        return await session.get(callback_url)

def fetch_urllib(webhook_url):
    return urlopen(webhook_url)
'''


class TestSSRFAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = SSRFAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SSRFAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "dynamic_requests_url" in patterns
        assert "dynamic_httpx_url" in patterns
        assert "dynamic_aiohttp_url" in patterns
        assert "dynamic_urllib_url" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SSRFAnalyzer(str(tmp_path))
        assert "SSRF risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SSRFAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 3
