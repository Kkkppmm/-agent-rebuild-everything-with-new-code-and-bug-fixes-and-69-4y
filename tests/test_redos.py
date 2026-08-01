"""Tests for ReDoSAnalyzer."""

from pathlib import Path

from devai.redos import ReDoSAnalyzer

SAFE_CODE = '''
import re

PATTERN = r"^[a-z]+$"

def match_email(text):
    return re.match(r"[a-z]+@[a-z]+", text)
'''

RISKY_CODE = '''
import re

def bad_pattern(text):
    return re.search(r"(a+)+b", text)

def nested_star(text):
    return re.compile(r"(.*)*")
'''


class TestReDoSAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        assert "ReDoS" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
