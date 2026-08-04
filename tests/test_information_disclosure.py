"""Tests for InformationDisclosureAnalyzer."""

from pathlib import Path

from devai.information_disclosure import InformationDisclosureAnalyzer

SAFE_CODE = '''
def handler():
    return {"error": "An error occurred"}
'''

RISKY_CODE = '''
import traceback

def handler(e):
    return str(e)

def debug():
  print(password)
  return traceback.format_exc()
'''


class TestInformationDisclosureAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = InformationDisclosureAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_disclosure(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InformationDisclosureAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InformationDisclosureAnalyzer(str(tmp_path))
        assert "Information disclosure:" in analyzer.summary()
        assert "Information disclosure analysis:" in analyzer.to_context()
