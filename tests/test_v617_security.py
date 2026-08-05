"""Tests for v6.17.0 security analyzers."""

from pathlib import Path

from devai import InsecureBindAnalyzer, SecurityScanner


class TestInsecureBindAnalyzer:
    def test_clean_localhost_bind(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "app.run(host='127.0.0.1', port=8000)\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_flask_all_interfaces(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "app.run(host='0.0.0.0', port=8000)\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "all_interfaces_host" for f in findings)
        assert any(f.host == "0.0.0.0" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_uvicorn_all_interfaces(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            'import uvicorn\nuvicorn.run(app, host="0.0.0.0", port=8080)\n',
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "all_interfaces_host" for f in findings)

    def test_detects_socket_bind(self, tmp_path: Path):
        (tmp_path / "server.py").write_text(
            "sock.bind(('0.0.0.0', 9000))\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "all_interfaces_bind" for f in findings)

    def test_detects_httpserver_tuple(self, tmp_path: Path):
        (tmp_path / "server.py").write_text(
            "from http.server import HTTPServer\n"
            "HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "all_interfaces_server" for f in findings)

    def test_detects_ipv6_all_interfaces(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            'app.run(host="::", port=8000)\n',
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.host == "::" for f in findings)


class TestInsecureBindScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "app.run(host='0.0.0.0', port=8000)\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_bind",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_bind" for cat in report.categories)
