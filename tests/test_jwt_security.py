"""Tests for JWTSecurityAnalyzer."""

from pathlib import Path

from devai.jwt_security import JWTSecurityAnalyzer


SAFE_CODE = '''
import jwt

def decode_token(token, secret):
    return jwt.decode(token, secret, algorithms=["HS256"])
'''

RISKY_CODE = '''
import jwt

def bad_decode(token):
    return jwt.decode(token, options={"verify_signature": False})

def none_alg(token):
    return jwt.encode({"sub": "user"}, "", algorithm="none")

def unverified(token):
    return jwt.get_unverified_header(token)
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
        patterns = {f.pattern for f in findings}
        assert "jwt_options_verify_signature" in patterns or "jwt_disabled_verify_signature" in patterns
        assert "jwt_none_algorithm" in patterns
        assert "jwt_unverified_access" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert "JWT security:" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
