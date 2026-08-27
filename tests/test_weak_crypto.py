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
    return hashlib.md5(password.encode()).hexdigest()

def sign_token(data: str) -> str:
    return hashlib.sha1(data.encode()).hexdigest()
'''


class TestWeakCryptoAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = WeakCryptoAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_weak_hashes(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = WeakCryptoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        names = {f.name for f in findings}
        assert "hashlib.md5" in names
        assert "hashlib.sha1" in names
        assert analyzer.health_score() < 100.0

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = WeakCryptoAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = WeakCryptoAnalyzer(str(tmp_path))
        assert "Weak crypto:" in analyzer.summary()
        assert "Weak crypto analysis:" in analyzer.to_context()
