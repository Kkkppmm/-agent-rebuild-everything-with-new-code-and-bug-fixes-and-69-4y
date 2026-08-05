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

    def test_detects_flask_run_all_interfaces(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "app.run(host='0.0.0.0', port=8000)\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_bind_host" for f in findings)
        assert any(f.host == "0.0.0.0" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_uvicorn_run(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "uvicorn.run('app:app', host='0.0.0.0', port=8080)\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_bind_host" for f in findings)

    def test_detects_socket_bind(self, tmp_path: Path):
        (tmp_path / "server.py").write_text(
            "sock.bind(('0.0.0.0', 9000))\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "socket_bind_all_interfaces" for f in findings)

    def test_detects_http_server_tuple(self, tmp_path: Path):
        (tmp_path / "server.py").write_text(
            "HTTPServer(('0.0.0.0', 8080), Handler)\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "server_all_interfaces" for f in findings)


class TestInsecureBindScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "app.run(host='0.0.0.0')\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_bind",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_bind" for cat in report.categories)
