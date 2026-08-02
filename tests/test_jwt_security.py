"""Tests for JWTSecurityAnalyzer."""

from pathlib import Path

from devai.jwt_security import JWTSecurityAnalyzer


SAFE_CODE = '''
import jwt
import os

SECRET = os.environ["JWT_SECRET"]

def verify_token(token: str):
    return jwt.decode(token, SECRET, algorithms=["HS256"])
'''

RISKY_CODE = '''
import jwt

JWT_SECRET = "hardcoded-signing-secret-key"

def bad_decode(token):
    return jwt.decode(token, options={"verify_signature": False})

def no_verify(token, key):
    return jwt.decode(token, key, verify=False)

def none_alg(token, key):
    return jwt.decode(token, key, algorithms=["none"])

def sign_token(payload):
    return jwt.encode(payload, "another-hardcoded-secret", algorithm="HS256")

def peek_header(token):
    return jwt.get_unverified_header(token)
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
        patterns = {f.pattern for f in findings}
        assert "jwt_verify_signature_disabled" in patterns
        assert "jwt_verify_disabled" in patterns
        assert "jwt_algorithm_none" in patterns
        assert "hardcoded_jwt_secret" in patterns
        assert "unverified_jwt_access" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert "JWT security" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 4
