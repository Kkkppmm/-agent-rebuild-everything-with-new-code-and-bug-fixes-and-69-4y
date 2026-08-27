"""Tests for InsecureRandomAnalyzer."""

from pathlib import Path

from devai.insecure_random import InsecureRandomAnalyzer

SAFE_CODE = '''
import secrets

def make_token():
    return secrets.token_hex(32)

def pick_item(items):
    import random
    return random.choice(items)
'''

RISKY_CODE = '''
import random

def generate_api_key():
    return random.randint(0, 10**16)

def create_session_token():
    token = random.choice("abcdef")
    return token

def reset_password():
    password = random.getrandbits(128)
    return password
'''


class TestInsecureRandomAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = InsecureRandomAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureRandomAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert any(f.severity == "high" for f in findings)
        assert analyzer.health_score() < 100.0

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureRandomAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureRandomAnalyzer(str(tmp_path))
        assert "Insecure random" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
