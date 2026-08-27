"""Tests for v6.0.0 security analyzers."""

from pathlib import Path

from devai import (
    CORSAnalyzer,
    CSRFAnalyzer,
    InsecureCookieAnalyzer,
    JWTSecurityAnalyzer,
    NoSQLInjectionAnalyzer,
    ReDoSAnalyzer,
    XSSAnalyzer,
)


class TestNoSQLInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(
            "def get_user(db, uid):\n    return db.users.find_one({'_id': uid})\n",
            encoding="utf-8",
        )
        assert NoSQLInjectionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_dynamic_query(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(
            'def search(db, q):\n    return db.users.find(f"{{name: \'{q}\'}}")\n',
            encoding="utf-8",
        )
        findings = NoSQLInjectionAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1


class TestInsecureCookieAnalyzer:
    def test_detects_missing_flags(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def set_session(response):\n    response.set_cookie('session', 'abc')\n",
            encoding="utf-8",
        )
        findings = InsecureCookieAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1

    def test_secure_cookie_ok(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def set_session(response):\n"
            "    response.set_cookie('s', 'v', secure=True, httponly=True)\n",
            encoding="utf-8",
        )
        assert InsecureCookieAnalyzer(str(tmp_path)).analyze() == []


class TestJWTSecurityAnalyzer:
    def test_detects_verify_disabled(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "import jwt\n\ndef decode_token(token):\n"
            "    return jwt.decode(token, options={'verify_signature': False})\n",
            encoding="utf-8",
        )
        findings = JWTSecurityAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "verify_disabled" for f in findings)

    def test_detects_hardcoded_secret(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            'jwt_secret = "supersecretkey123"\n',
            encoding="utf-8",
        )
        findings = JWTSecurityAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_secret" for f in findings)


class TestCORSAnalyzer:
    def test_detects_wildcard(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask_cors import CORS\nCORS(app, origins='*')\n",
            encoding="utf-8",
        )
        findings = CORSAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1


class TestCSRFAnalyzer:
    def test_detects_missing_csrf(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "from flask import Blueprint\nbp = Blueprint('api', __name__)\n"
            "@bp.route('/submit', methods=['POST'])\n"
            "def submit():\n    return 'ok'\n",
            encoding="utf-8",
        )
        findings = CSRFAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1


class TestReDoSAnalyzer:
    def test_detects_nested_quantifier(self, tmp_path: Path):
        (tmp_path / "util.py").write_text(
            'import re\nPAT = re.compile(r"(a+)+")\n',
            encoding="utf-8",
        )
        findings = ReDoSAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1


class TestXSSAnalyzer:
    def test_detects_reflected_xss(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "from flask import request\nfrom flask import Response\n"
            "def search():\n    return Response(request.args.get('q'))\n",
            encoding="utf-8",
        )
        findings = XSSAnalyzer(str(tmp_path)).analyze()
        assert len(findings) >= 1

    def test_safe_response(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "from flask import Response\n"
            "def home():\n    return Response('Hello')\n",
            encoding="utf-8",
        )
        assert XSSAnalyzer(str(tmp_path)).analyze() == []
