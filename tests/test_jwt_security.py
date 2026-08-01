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

def decode_unsafe(token):
    return jwt.decode(token, options={"verify_signature": False})

def decode_no_verify(token, key):
    return jwt.decode(token, key, verify=False)

def encode_none(payload):
    return jwt.encode(payload, "", algorithm="none")

def decode_none(token, key):
    return jwt.decode(token, key, algorithms=["none", "HS256"])
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
        assert "verify_signature_disabled" in patterns or "verify_disabled" in patterns
        assert "none_algorithm" in patterns or "none_algorithm_accepted" in patterns
        assert len(analyzer.critical_findings()) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert "JWT security" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
