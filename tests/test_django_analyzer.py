"""Tests for DjangoAnalyzer."""

from pathlib import Path

from devai.django_analyzer import DjangoAnalyzer, DjangoFinding


INSECURE_DJANGO_SETTINGS = """\
import os

SECRET_KEY = "django-insecure-hardcoded-secret-key-12345"

DEBUG = True

ALLOWED_HOSTS = ["*"]

CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SAMESITE = "None"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "mydb",
        "USER": "admin",
        "PASSWORD": "super_secret_db_password",
        "HOST": "localhost",
    }
}

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "debug_toolbar",
]

AUTH_PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"
"""

INSECURE_DJANGO_VIEWS = """\
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.safestring import mark_safe
import requests


@csrf_exempt
def debug_env(request):
    return HttpResponse(mark_safe(request.GET.get("q", "")))


@csrf_exempt
def proxy_view(request):
    url = request.GET.get("url", "http://192.168.1.10/internal")
    return HttpResponse(requests.get(url, verify=False).content)
"""

INSECURE_DJANGO_URLS = """\
from django.contrib import admin
from django.urls import path
from django.views.static import serve
from . import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("debug/env", views.debug_env),
    path("internal/status", views.proxy_view),
    path("static/<path:path>", serve, {"document_root": "/"}),
]
"""

HARDENED_DJANGO_SETTINGS = """\
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"

ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "example.com").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ["DB_NAME"],
        "USER": os.environ["DB_USER"],
        "PASSWORD": os.environ["DB_PASSWORD"],
        "HOST": os.environ.get("DB_HOST", "localhost"),
    }
}

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
X_FRAME_OPTIONS = "DENY"
"""


class TestDjangoAnalyzer:
    def test_detects_insecure_django_project(self, tmp_path: Path):
        (tmp_path / "manage.py").write_text(
            "#!/usr/bin/env python\nimport os\nos.environ.setdefault("
            "'DJANGO_SETTINGS_MODULE', 'myproject.settings')\n",
            encoding="utf-8",
        )
        settings_dir = tmp_path / "myproject"
        settings_dir.mkdir()
        (settings_dir / "settings.py").write_text(INSECURE_DJANGO_SETTINGS, encoding="utf-8")
        (settings_dir / "views.py").write_text(INSECURE_DJANGO_VIEWS, encoding="utf-8")
        (settings_dir / "urls.py").write_text(INSECURE_DJANGO_URLS, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["django>=5.0", "requests>=2.31.0"]\n',
            encoding="utf-8",
        )

        analyzer = DjangoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "secret_key_hardcoded" in kinds or "hardcoded_secret" in kinds
        assert "debug_enabled" in kinds
        assert "allowed_hosts_wildcard" in kinds
        assert "csrf_exempt" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = DjangoAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_django_project_scores_well(self, tmp_path: Path):
        (tmp_path / "manage.py").write_text(
            "#!/usr/bin/env python\nimport os\nos.environ.setdefault("
            "'DJANGO_SETTINGS_MODULE', 'config.settings')\n",
            encoding="utf-8",
        )
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.py").write_text(HARDENED_DJANGO_SETTINGS, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["django>=5.0"]\n',
            encoding="utf-8",
        )

        analyzer = DjangoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "manage.py").write_text(
            "#!/usr/bin/env python\nimport os\nos.environ.setdefault("
            "'DJANGO_SETTINGS_MODULE', 'app.settings')\n",
            encoding="utf-8",
        )
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "settings.py").write_text(
            "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']\nDEBUG = False\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["django"]\n',
            encoding="utf-8",
        )

        analyzer = DjangoAnalyzer(str(tmp_path))
        assert "Django:" in analyzer.summary()
        assert "Django project analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = DjangoAnalyzer(".").generate_hardened_template()
        assert "SECRET_KEY" in template
        assert "os.environ" in template
        assert "SESSION_COOKIE_SECURE = True" in template

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
