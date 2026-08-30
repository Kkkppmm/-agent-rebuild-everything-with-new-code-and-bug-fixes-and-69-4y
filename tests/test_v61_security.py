"""Tests for v6.1.0 security analyzers."""

from pathlib import Path

from devai import (
    DebugExposureAnalyzer,
    LDAPInjectionAnalyzer,
    XXEAnalyzer,
)


class TestXXEAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def process(data):\n    return data\n",
            encoding="utf-8",
        )
        assert XXEAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_unsafe_xml_parse(self, tmp_path: Path):
        (tmp_path / "parser.py").write_text(
            "import xml.etree.ElementTree as ET\n"
            "def parse_xml(data):\n    return ET.fromstring(data)\n",
            encoding="utf-8",
        )
        findings = XXEAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1
        assert any(f.pattern in {"unsafe_xml_parse", "unsafe_xml_import"} for f in findings)


class TestLDAPInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def search(conn, uid):\n    return conn.search_s('dc=example', '(uid=alice)')\n",
            encoding="utf-8",
        )
        assert LDAPInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_dynamic_filter(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            'def search(conn, username):\n'
            '    return conn.search_s("dc=example", f"(uid={username})")\n',
            encoding="utf-8",
        )
        findings = LDAPInjectionAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1


class TestDebugExposureAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def main():\n    return 'ok'\n",
            encoding="utf-8",
        )
        assert DebugExposureAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_debug_flag(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "DEBUG = True\n",
            encoding="utf-8",
        )
        findings = DebugExposureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "debug_enabled" for f in findings)

    def test_detects_flask_debug_run(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n"
            "if __name__ == '__main__':\n    app.run(debug=True)\n",
            encoding="utf-8",
        )
        findings = DebugExposureAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "flask_debug_run" for f in findings)
