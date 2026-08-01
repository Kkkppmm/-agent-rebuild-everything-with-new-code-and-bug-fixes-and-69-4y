"""Tests for XXEAnalyzer."""

from pathlib import Path

from devai.xxe import XXEAnalyzer


SAFE_CODE = '''
import defusedxml.ElementTree as ET

def parse_xml(data):
    return ET.fromstring(data)
'''

RISKY_CODE = '''
import xml.etree.ElementTree as ET
from lxml import etree
import xml.dom.minidom as minidom

def parse_user_xml(user_xml):
    return ET.fromstring(user_xml)

def parse_file(path):
    return etree.parse(path)

def parse_dom(data):
    return minidom.parseString(data)
'''

STATIC_XML = '''
import xml.etree.ElementTree as ET

CONFIG = "<root><item>ok</item></root>"

def load_config():
    return ET.fromstring(CONFIG)
'''


class TestXXEAnalyzer:
    def test_clean_code_with_defusedxml(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "unsafe_etree_fromstring" in patterns
        assert "unsafe_lxml_parse" in patterns
        assert "unsafe_minidom_parse_string" in patterns
        assert len(analyzer.critical_findings()) >= 1

    def test_static_xml_not_flagged(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(STATIC_XML, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        assert "XXE:" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
