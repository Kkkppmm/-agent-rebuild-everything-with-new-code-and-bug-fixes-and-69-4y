"""Tests for TimingAttackAnalyzer."""

from pathlib import Path

from devai.timing_attack import TimingAttackAnalyzer


SAFE_CODE = '''
import hmac

def check_token(expected, provided):
    return hmac.compare_digest(expected, provided)
'''

RISKY_CODE = '''
def check_password(stored_hash, user_password):
    return stored_hash == user_password

def verify_token(api_key, provided_token):
    return api_key == provided_token
'''


class TestTimingAttackAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        assert "Timing attack risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
