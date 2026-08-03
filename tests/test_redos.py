"""Tests for ReDoSAnalyzer."""

from pathlib import Path

from devai.redos import ReDoSAnalyzer

SAFE_CODE = '''
import re

def validate_email(email: str) -> bool:
    return re.match(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$", email) is not None
'''

RISKY_CODE = '''
import re

EMAIL_REGEX = re.compile(r"(a+)+$")

def slow_match(text: str) -> bool:
    return bool(re.search(r"(.*)+", text))
'''


class TestReDoSAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_nested_quantifiers(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert analyzer.health_score() < 100.0

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = ReDoSAnalyzer(str(tmp_path))
        assert "ReDoS:" in analyzer.summary()
        assert "ReDoS analysis:" in analyzer.to_context()
