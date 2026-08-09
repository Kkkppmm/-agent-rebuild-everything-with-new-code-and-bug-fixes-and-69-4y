"""Tests for v6.15.0 security analyzers."""

from pathlib import Path

from devai import InsecureWebSocketAnalyzer, SecurityScanner


class TestInsecureWebSocketAnalyzer:
    def test_clean_code_no_ws_urls(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            'WS_URL = "wss://api.example.com/ws"\n',
            encoding="utf-8",
        )
        findings = InsecureWebSocketAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_insecure_ws_url(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            'url = "ws://api.example.com/socket"\n',
            encoding="utf-8",
        )
        findings = InsecureWebSocketAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_ws_url" for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_detects_localhost_ws(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            'url = "ws://localhost:8765"\n',
            encoding="utf-8",
        )
        findings = InsecureWebSocketAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "localhost_ws" for f in findings)

    def test_allows_localhost_ws_in_tests(self, tmp_path: Path):
        (tmp_path / "test_client.py").write_text(
            'url = "ws://localhost:8765"\n',
            encoding="utf-8",
        )
        findings = InsecureWebSocketAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_disabled_ws_tls(self, tmp_path: Path):
        (tmp_path / "ws.py").write_text(
            "import ssl\n"
            "import websockets\n"
            "websockets.connect(url, ssl=False)\n",
            encoding="utf-8",
        )
        findings = InsecureWebSocketAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "ws_tls_disabled" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_allows_wss_urls(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            'url = "wss://secure.example.com/live"\n',
            encoding="utf-8",
        )
        findings = InsecureWebSocketAnalyzer(str(tmp_path)).analyze()
        assert not findings


class TestInsecureWebSocketScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            'url = "ws://chat.example.com/stream"\n',
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_websocket",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_websocket" for cat in report.categories)
