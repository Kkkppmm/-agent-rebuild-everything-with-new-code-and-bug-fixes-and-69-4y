"""Tests for v6.2.0 security analyzers."""

from pathlib import Path

from devai import (
    SSTIAnalyzer,
    TLSVerificationAnalyzer,
)


class TestTLSVerificationAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "import httpx\n\ndef fetch(url):\n    return httpx.get(url)\n",
            encoding="utf-8",
        )
        assert TLSVerificationAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_verify_false(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "import requests\n\ndef fetch(url):\n    return requests.get(url, verify=False)\n",
            encoding="utf-8",
        )
        findings = TLSVerificationAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "verify_false" for f in findings)

    def test_detects_unverified_context(self, tmp_path: Path):
        (tmp_path / "ssl.py").write_text(
            "import ssl\n\ndef get_ctx():\n    return ssl._create_unverified_context()\n",
            encoding="utf-8",
        )
        findings = TLSVerificationAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unverified_ssl_context" for f in findings)


class TestSSTIAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def render():\n    return 'hello'\n",
            encoding="utf-8",
        )
        assert SSTIAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_render_template_string(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import render_template_string, request\n"
            "def view():\n"
            "    return render_template_string(request.args.get('tpl'))\n",
            encoding="utf-8",
        )
        findings = SSTIAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "jinja_render_string" for f in findings)

    def test_detects_jinja_template(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from jinja2 import Template\n"
            "def render(user_input):\n"
            "    return Template(user_input).render()\n",
            encoding="utf-8",
        )
        findings = SSTIAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern in {"jinja_template", "template_constructor"} for f in findings)
