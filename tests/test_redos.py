"""Tests for ReDoSAnalyzer."""

from pathlib import Path

from devai.redos import ReDoSAnalyzer


SAFE_CODE = '''
import re

PATTERN = r"^\\d+$"

def validate_email(email):
    return re.match(r"[a-z]+@[a-z]+", email)
'''

RISKY_CODE = '''
import re

BAD_PATTERN = r"(a+)+$"
NESTED = r"(a|aa)+*"

def check_input(user_input):
    return re.match(r"(x+)+y", user_input)
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
        patterns = {f.pattern for f in findings}
        assert "nested_quantifier" in patterns or "overlapping_alternation" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        assert "ReDoS risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
