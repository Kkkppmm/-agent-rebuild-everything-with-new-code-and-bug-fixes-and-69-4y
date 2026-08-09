"""Tests for v6.17–6.19.0 security analyzers."""

from pathlib import Path

from devai import (
    InsecureBindAnalyzer,
    MissingTimeoutAnalyzer,
    SecurityScanner,
    TemplateAutoescapeAnalyzer,
)


class TestMissingTimeoutAnalyzer:
    def test_clean_code_with_timeout(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "import requests\nrequests.get('https://api.example.com', timeout=10)\n",
            encoding="utf-8",
        )
        findings = MissingTimeoutAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_http_without_timeout(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "import requests\nrequests.get('https://api.example.com')\n",
            encoding="utf-8",
        )
        findings = MissingTimeoutAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "http_no_timeout" for f in findings)

    def test_detects_subprocess_without_timeout(self, tmp_path: Path):
        (tmp_path / "run.py").write_text(
            "import subprocess\nsubprocess.run(['ls'])\n",
            encoding="utf-8",
        )
        findings = MissingTimeoutAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "subprocess_no_timeout" for f in findings)

    def test_detects_httpx_without_timeout(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "import httpx\nhttpx.post('https://api.example.com', json={})\n",
            encoding="utf-8",
        )
        findings = MissingTimeoutAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "http_no_timeout" for f in findings)


class TestInsecureBindAnalyzer:
    def test_clean_bind_localhost(self, tmp_path: Path):
        (tmp_path / "server.py").write_text(
            "app.run(host='127.0.0.1', port=8000)\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_host_all_interfaces(self, tmp_path: Path):
        (tmp_path / "server.py").write_text(
            "app.run(host='0.0.0.0', port=8000)\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "host_all_interfaces" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_bind_tuple(self, tmp_path: Path):
        (tmp_path / "socket.py").write_text(
            "sock.bind(('0.0.0.0', 8080))\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "bind_all_interfaces" for f in findings)

    def test_detects_uvicorn_run(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "import uvicorn\nuvicorn.run(app, host='0.0.0.0', port=8000)\n",
            encoding="utf-8",
        )
        findings = InsecureBindAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "host_all_interfaces" for f in findings)


class TestTemplateAutoescapeAnalyzer:
    def test_clean_environment_with_autoescape(self, tmp_path: Path):
        (tmp_path / "templates.py").write_text(
            "from jinja2 import Environment\nenv = Environment(autoescape=True)\n",
            encoding="utf-8",
        )
        findings = TemplateAutoescapeAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_missing_autoescape(self, tmp_path: Path):
        (tmp_path / "templates.py").write_text(
            "from jinja2 import Environment\nenv = Environment()\n",
            encoding="utf-8",
        )
        findings = TemplateAutoescapeAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "autoescape_missing" for f in findings)

    def test_detects_disabled_autoescape(self, tmp_path: Path):
        (tmp_path / "templates.py").write_text(
            "from jinja2 import Environment\nenv = Environment(autoescape=False)\n",
            encoding="utf-8",
        )
        findings = TemplateAutoescapeAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "autoescape_disabled" for f in findings)
        assert any(f.severity == "high" for f in findings)


class TestV619SecurityScanner:
    def test_integrated_missing_timeout(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "import requests\nrequests.get('https://example.com')\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("missing_timeout",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "missing_timeout" for cat in report.categories)

    def test_integrated_insecure_bind(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "app.run(host='0.0.0.0')\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_bind",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_bind" for cat in report.categories)

    def test_integrated_template_autoescape(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "from jinja2 import Environment\nEnvironment()\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("template_autoescape",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "template_autoescape" for cat in report.categories)
