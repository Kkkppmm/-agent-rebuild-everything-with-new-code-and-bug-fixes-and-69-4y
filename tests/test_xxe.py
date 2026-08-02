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
from xml.dom import minidom
import lxml.etree as etree

def bad_etree(data):
    return ET.parse(data)

def bad_minidom(data):
    return minidom.parseString(data)

def bad_lxml(data):
    return etree.fromstring(data)

def bad_parser():
  return ET.XMLParser()
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
        assert "parse_unsafe_xml" in patterns
        assert "fromstring_unsafe_xml" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        assert "XXE risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 2
