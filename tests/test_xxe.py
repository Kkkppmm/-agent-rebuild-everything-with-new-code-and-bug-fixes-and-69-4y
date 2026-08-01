"""Tests for XXEAnalyzer."""

from pathlib import Path

from devai.xxe import XXEAnalyzer


SAFE_CODE = '''
import xml.etree.ElementTree as ET

CONFIG = "<root><item>1</item></root>"

def parse_config():
    return ET.fromstring(CONFIG)
'''

RISKY_CODE = '''
import xml.etree.ElementTree as ET

def parse_user_xml(user_xml):
    return ET.fromstring(user_xml)

def parse_upload(upload_data):
    return ET.parse(upload_data)
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
        assert "dynamic_stdlib_xml" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        assert "XXE risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = XXEAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 1
