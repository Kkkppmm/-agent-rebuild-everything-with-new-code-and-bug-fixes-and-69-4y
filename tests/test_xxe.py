"""Tests for XXEAnalyzer."""

from pathlib import Path

from devai.xxe import XXEAnalyzer


SAFE_CODE = '''
import defusedxml.ElementTree as ET

def load_xml(path):
    return ET.parse(path)
'''

RISKY_CODE = '''
import xml.etree.ElementTree as ET
from xml.dom import minidom
import lxml.etree

def load_etree(path):
    return ET.parse(path)

def load_string(data):
    return ET.fromstring(data)

def load_minidom(path):
    return minidom.parse(path)

def load_lxml(data):
    return lxml.etree.fromstring(data)
'''

SAFE_PARSER_CODE = '''
import xml.etree.ElementTree as ET

def load_xml(data):
    parser = ET.XMLParser(resolve_entities=False)
    return ET.fromstring(data, parser=parser)
'''


class TestXXEAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "etree_parse" in patterns
        assert "etree_fromstring" in patterns
        assert "minidom_parse" in patterns
        assert "lxml_fromstring" in patterns
        assert analyzer.health_score() < 100.0

    def test_safe_parser_not_flagged(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_PARSER_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        patterns = {f.pattern for f in analyzer.analyze()}
        assert "unsafe_xml_parser" not in patterns

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        assert "XXE risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
