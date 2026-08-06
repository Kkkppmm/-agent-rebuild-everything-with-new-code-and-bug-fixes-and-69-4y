"""Tests for v6.9.0 security analyzers."""

from pathlib import Path

from devai import InsecureHTTPAnalyzer


class TestInsecureHTTPAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            'API_URL = "https://api.example.com/v1"\n'
            "def fetch():\n"
            "    return requests.get(API_URL)\n",
            encoding="utf-8",
        )
        assert InsecureHTTPAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_insecure_url(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            'WEBHOOK = "http://api.example.com/hook"\n',
            encoding="utf-8",
        )
        findings = InsecureHTTPAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_http_url" for f in findings)

    def test_allows_localhost_in_tests(self, tmp_path: Path):
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        (test_dir / "test_api.py").write_text(
            'BASE = "http://localhost:8000"\n',
            encoding="utf-8",
        )
        findings = InsecureHTTPAnalyzer(str(tmp_path)).analyze()
        assert findings == []

    def test_detects_verify_false(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "def fetch(url):\n"
            "    return requests.get(url, verify=False)\n",
            encoding="utf-8",
        )
        findings = InsecureHTTPAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "tls_verify_disabled" for f in findings)

    def test_detects_ssl_disabled(self, tmp_path: Path):
        (tmp_path / "smtp.py").write_text(
            "def connect():\n"
            "    smtp = SMTP(host='mail.example.com', ssl=False)\n",
            encoding="utf-8",
        )
        findings = InsecureHTTPAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "ssl_disabled" for f in findings)
