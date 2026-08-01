"""Tests for JWTSecurityAnalyzer."""

from pathlib import Path

from devai.jwt_security import JWTSecurityAnalyzer

SAFE_CODE = '''
import jwt

def decode_token(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])
'''

RISKY_CODE = '''
import jwt

def decode_unsafe(token):
    return jwt.decode(token, options={"verify_signature": False})

def decode_none(token):
    return jwt.decode(token, algorithms=["none"])
'''


class TestJWTSecurityAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert any(f.severity == "critical" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert "JWT security" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
