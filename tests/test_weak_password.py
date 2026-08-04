"""Tests for WeakPasswordAnalyzer."""

from pathlib import Path

from devai.weak_password import WeakPasswordAnalyzer


SAFE_CODE = '''
from werkzeug.security import generate_password_hash

def register(password):
    if len(password) < 12:
        raise ValueError("too short")
    return generate_password_hash(password)
'''

RISKY_CODE = '''
def register(user, password):
    if len(password) < 6:
        raise ValueError("too short")
    user.password = password
'''


class TestWeakPasswordAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = WeakPasswordAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = WeakPasswordAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "weak_min_length" in patterns
        assert "plaintext_storage" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = WeakPasswordAnalyzer(str(tmp_path))
        assert "Weak password" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
