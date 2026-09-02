"""Tests for DjangoAnalyzer."""

from pathlib import Path

from devai.django_analyzer import DjangoAnalyzer, DjangoFinding


INSECURE_DJANGO_SETTINGS = """\
import os
import subprocess

SECRET_KEY = "django-insecure-hardcoded-secret-key"
DEBUG = True
ALLOWED_HOSTS = ["*"]

CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False
X_FRAME_OPTIONS = None

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "mydb",
        "USER": "admin",
        "PASSWORD": "super_secret_password",
        "HOST": "db.example.com",
    }
}

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
]
"""

INSECURE_DJANGO_VIEWS = """\
import subprocess
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.safestring import mark_safe
from django.db import connection


@csrf_exempt
def admin_panel(request):
    return HttpResponse("admin")


@csrf_exempt
def debug_env(request):
    import os
    return HttpResponse(str(os.environ))


def run_cmd(request):
    cmd = request.GET.get("cmd")
    return HttpResponse(subprocess.check_output(cmd, shell=True))


def preview(request):
    html = request.GET.get("html")
    return HttpResponse(mark_safe(html))


def proxy(request):
    import requests
    return HttpResponse(requests.get("http://192.168.1.10/api", verify=False).text)


def raw_query(request):
    user_id = request.GET.get("id")
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""

HARDENED_DJANGO_SETTINGS = """\
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = False
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "example.com").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ["DB_NAME"],
        "USER": os.environ["DB_USER"],
        "PASSWORD": os.environ["DB_PASSWORD"],
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": os.environ.get("DB_PORT", "5432"),
    }
}

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
SECURE_SSL_REDIRECT = True
X_FRAME_OPTIONS = "DENY"
"""


class TestDjangoAnalyzer:
    def test_detects_insecure_django_project(self, tmp_path: Path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.py").write_text(INSECURE_DJANGO_SETTINGS, encoding="utf-8")
        (tmp_path / "views.py").write_text(INSECURE_DJANGO_VIEWS, encoding="utf-8")
        (tmp_path / "manage.py").write_text(
            '#!/usr/bin/env python\nimport os\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")\n',
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["django>=5.0.0", "django-cors-headers>=4.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = DjangoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "django_insecure_secret" in kinds or "hardcoded_secret" in kinds
        assert "debug_mode" in kinds
        assert "allowed_hosts_wildcard" in kinds
        assert "csrf_exempt" in kinds
        assert "mark_safe_xss" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = DjangoAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_django_settings_scores_well(self, tmp_path: Path):
        config_dir = tmp_path / "project"
        config_dir.mkdir()
        (config_dir / "settings.py").write_text(HARDENED_DJANGO_SETTINGS, encoding="utf-8")
        (tmp_path / "manage.py").write_text(
            '#!/usr/bin/env python\nimport os\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "project.settings")\n',
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["django>=5.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = DjangoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']\nDEBUG = False\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["django"]\n',
            encoding="utf-8",
        )

        analyzer = DjangoAnalyzer(str(tmp_path))
        assert "Django:" in analyzer.summary()
        assert "Django application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = DjangoAnalyzer(".").generate_hardened_template()
        assert "SECRET_KEY" in template
        assert "SecurityMiddleware" in template
        assert "SECURE_SSL_REDIRECT = True" in template

    def test_finding_format(self):
        finding = DjangoFinding(
            kind="test",
            severity="high",
            message="test message",
            path="settings.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "settings.py:1" in finding.format()
