"""Tests for Web2pyAnalyzer."""

from pathlib import Path

from devai.web2py_analyzer import Web2pyAnalyzer, Web2pyFinding


INSECURE_WEB2PY_CONTROLLER = """\
import os
import subprocess

from gluon import current
from gluon.http import redirect
from gluon.html import BEAUTIFY


def admin():
    return str(current.request.env)


def run_cmd():
    cmd = current.request.vars.cmd
    subprocess.run(cmd, shell=True)


def go():
    redirect(current.request.vars.url)


def show():
    return BEAUTIFY(current.request.vars.content)


def update_user():
    current.db.auth_user.update_record(**current.request.vars)
"""

INSECURE_WEB2PY_MODELS = """\
from gluon import current
from gluon.tools import Auth

API_KEY = "hardcoded_secret_value"

db = DAL('mysql://admin:super_secret@db.example.com/myapp')

auth = Auth(db, hmac_key="static_hmac_key_12345")
auth.settings.disable_password_verification = False
auth.settings.password_min_length = 2
auth.settings.hmac_key = "another_static_key"

current.session.secure = False
current.session.httponly = False
current.global_settings.debug = True
request.csrfguard_disabled = True
ajax_server_enabled = True
"""

HARDENED_WEB2PY_MODELS = """\
import os

from gluon import current
from gluon.tools import Auth

db = DAL(os.environ.get("DATABASE_URL", "sqlite://storage.sqlite"))
auth = Auth(db, hmac_key=os.environ.get("AUTH_HMAC_KEY"))
auth.settings.password_min_length = 12
current.session.secure = True
current.session.httponly = True
"""


class TestWeb2pyAnalyzer:
    def test_detects_insecure_web2py_app(self, tmp_path: Path):
        app_dir = tmp_path / "applications" / "myapp"
        (app_dir / "controllers").mkdir(parents=True)
        (app_dir / "models").mkdir(parents=True)
        (app_dir / "controllers" / "default.py").write_text(
            INSECURE_WEB2PY_CONTROLLER, encoding="utf-8"
        )
        (app_dir / "models" / "db.py").write_text(INSECURE_WEB2PY_MODELS, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["web2py"]\n',
            encoding="utf-8",
        )

        analyzer = Web2pyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "db_credentials" in kinds
        assert "shell_command" in kinds
        assert "open_redirect" in kinds
        assert "xss_unescaped" in kinds
        assert "mass_assignment" in kinds
        assert "csrf_disabled" in kinds
        assert "insecure_session" in kinds
        assert "weak_auth" in kinds
        assert "debug_mode" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = Web2pyAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_web2py_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "applications" / "myapp" / "models"
        app_dir.mkdir(parents=True)
        (app_dir / "db.py").write_text(HARDENED_WEB2PY_MODELS, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["web2py"]\n',
            encoding="utf-8",
        )

        analyzer = Web2pyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        app_dir = tmp_path / "models"
        app_dir.mkdir()
        (app_dir / "db.py").write_text(
            "from gluon.tools import Auth\n"
            "db = DAL('sqlite://storage.sqlite')\n"
            "auth = Auth(db)\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["web2py"]\n',
            encoding="utf-8",
        )

        analyzer = Web2pyAnalyzer(str(tmp_path))
        assert "web2py:" in analyzer.summary()
        assert "web2py application analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = Web2pyFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="models/db.py",
            lineno=1,
            line="SECRET = 'x'",
        )
        assert "[high]" in finding.format()
        assert "models/db.py:1" in finding.format()

    def test_generate_hardened_template(self):
        template = Web2pyAnalyzer(".").generate_hardened_template()
        assert "Auth(db" in template
        assert "AUTH_HMAC_KEY" in template
        assert "password_min_length" in template
