"""Tests for JWTSecurityAnalyzer."""

from pathlib import Path

from devai.jwt_security import JWTSecurityAnalyzer


SAFE_CODE = '''
import jwt

SECRET = os.environ["JWT_SECRET"]

def decode_token(token: str):
    return jwt.decode(token, SECRET, algorithms=["HS256"], verify=True)
'''

RISKY_CODE = '''
import jwt

JWT_SECRET = "short"

def decode_no_verify(token):
    return jwt.decode(token, options={"verify_signature": False})

def decode_algorithm_none(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["none"])

def encode_none(payload):
    return jwt.encode(payload, JWT_SECRET, algorithm="none")
'''


class TestJWTSecurityAnalyzer:
    def test_clean_code_skipped_without_jwt_issues(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def add(a, b):\n    return a + b\n", encoding="utf-8"
        )
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "jwt_signature_disabled" in patterns
        assert "jwt_algorithm_none" in patterns
        assert "jwt_encode_none" in patterns
        assert "jwt_hardcoded_secret" in patterns
        assert analyzer.health_score() < 100.0

    def test_critical_findings(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert len(analyzer.critical()) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = JWTSecurityAnalyzer(str(tmp_path))
        assert "JWT security" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
