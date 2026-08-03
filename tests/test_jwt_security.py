"""Tests for JWTSecurityAnalyzer."""

from pathlib import Path

from devai.jwt_security import JWTSecurityAnalyzer


SAFE_CODE = '''
import jwt

def verify_token(token, secret):
    return jwt.decode(token, secret, algorithms=["HS256"])
'''

RISKY_CODE = '''
import jwt

JWT_SECRET = "super-secret-key"

def verify_token(token):
    return jwt.decode(token, JWT_SECRET, verify=False)

def weak_decode(token, secret):
    return jwt.decode(token, secret, algorithms=["none"])
'''


class TestJWTSecurityAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 2
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert "JWT security risks" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
