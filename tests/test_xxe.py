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

def parse_xml(data):
    return ET.fromstring(data)

def parse_file(path):
    return ET.parse(path)
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
        assert "xml_unsafe_parse" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        assert "XXE:" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
