"""Tests for TimingAttackAnalyzer."""

from pathlib import Path

from devai.timing_attack import TimingAttackAnalyzer

SAFE_CODE = '''
import hmac

def verify_token(provided: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(provided, expected)
'''

RISKY_CODE = '''
def verify_password(password: str, stored_hash: str) -> bool:
    return password == stored_hash

def check_api_key(api_key: str, expected: str) -> bool:
    return api_key != expected
'''

SECURE_CONTEXT_CODE = '''
def authenticate_user(token: str, session_token: str) -> bool:
    return token == session_token
'''


class TestTimingAttackAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_compare(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert analyzer.health_score() < 100.0

    def test_security_context_function(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SECURE_CONTEXT_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        assert "Timing attacks:" in analyzer.summary()
        assert "Timing attack analysis:" in analyzer.to_context()

    def test_skips_test_files_by_default(self, tmp_path: Path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = TimingAttackAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
