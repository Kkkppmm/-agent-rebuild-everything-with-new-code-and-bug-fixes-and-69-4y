"""Tests for v6.18.0 security analyzers."""

from pathlib import Path

from devai import MissingTimeoutAnalyzer, SecurityScanner


class TestMissingTimeoutAnalyzer:
    def test_clean_requests_with_timeout(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "import requests\n"
            "requests.get('https://api.example.com', timeout=10)\n",
            encoding="utf-8",
        )
        findings = MissingTimeoutAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_requests_without_timeout(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "import requests\n"
            "requests.get('https://api.example.com')\n",
            encoding="utf-8",
        )
        findings = MissingTimeoutAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_http_timeout" for f in findings)
        assert any(f.call == "requests.get" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_subprocess_without_timeout(self, tmp_path: Path):
        (tmp_path / "runner.py").write_text(
            "import subprocess\n"
            "subprocess.run(['ls', '-la'])\n",
            encoding="utf-8",
        )
        findings = MissingTimeoutAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_subprocess_timeout" for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_detects_urlopen_without_timeout(self, tmp_path: Path):
        (tmp_path / "fetch.py").write_text(
            "from urllib.request import urlopen\n"
            "urlopen('https://example.com')\n",
            encoding="utf-8",
        )
        findings = MissingTimeoutAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_http_timeout" for f in findings)

    def test_detects_socket_create_connection(self, tmp_path: Path):
        (tmp_path / "net.py").write_text(
            "import socket\n"
            "socket.create_connection(('example.com', 80))\n",
            encoding="utf-8",
        )
        findings = MissingTimeoutAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_socket_timeout" for f in findings)


class TestMissingTimeoutScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "import requests\n"
            "requests.post('https://api.example.com', json={})\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("missing_timeout",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "missing_timeout" for cat in report.categories)
