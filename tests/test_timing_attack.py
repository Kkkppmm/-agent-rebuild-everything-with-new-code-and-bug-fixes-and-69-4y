"""Tests for TimingAttackAnalyzer."""

from pathlib import Path

from devai.timing_attack import TimingAttackAnalyzer


SAFE_CODE = '''
import hmac

def verify(token, expected):
    return hmac.compare_digest(token, expected)
'''

RISKY_CODE = '''
def check_password(password, stored_hash):
    return password == stored_hash

def check_token(user_token, api_token):
    return user_token != api_token
'''


class TestTimingAttackAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "eq_compare" in patterns
        assert "ne_compare" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        assert "Timing attack" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
