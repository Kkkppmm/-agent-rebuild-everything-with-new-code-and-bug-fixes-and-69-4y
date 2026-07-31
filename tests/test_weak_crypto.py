"""Tests for WeakCryptoAnalyzer."""

from pathlib import Path

from devai.weak_crypto import WeakCryptoAnalyzer

SAFE_CODE = '''
import hashlib

def hash_file(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
'''

RISKY_CODE = '''
import hashlib

def hash_password(password: str) -> str:
    password_hash = hashlib.md5(password.encode()).hexdigest()
    return password_hash

def verify_token(token: str) -> str:
    token_hash = hashlib.sha1(token.encode()).hexdigest()
    return token_hash
'''


class TestWeakCryptoAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = WeakCryptoAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_weak_algorithms(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = WeakCryptoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert any(f.severity == "high" for f in findings)
        assert analyzer.health_score() < 100.0

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = WeakCryptoAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = WeakCryptoAnalyzer(str(tmp_path))
        assert "Weak crypto" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
