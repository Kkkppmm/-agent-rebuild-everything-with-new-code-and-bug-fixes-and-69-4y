"""Tests for DjangoAnalyzer."""

from pathlib import Path

from devai.django_analyzer import DjangoAnalyzer, DjangoFinding


INSECURE_DJANGO_SETTINGS = """\
DEBUG = True
SECRET_KEY = 'django-insecure-hardcoded-secret-key-12345'
ALLOWED_HOSTS = ['*']

DATABASES = {
    'default': {
        'PASSWORD': 'db_password_hardcoded',
    }
}

CORS_ORIGIN_ALLOW_ALL = True
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
X_FRAME_OPTIONS = 'ALLOWALL'

WEBHOOK_URL = 'http://10.0.0.1/internal/callback'
API_BASE = 'http://example.com/api'

def render_bio(bio):
    return mark_safe(bio)
"""

HARDENED_DJANGO_SETTINGS = """\
import os

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")

SECURE_SSL_REDIRECT = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
CORS_ORIGIN_ALLOW_ALL = False
"""


class TestDjangoAnalyzer:
    def test_detects_insecure_django_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(INSECURE_DJANGO_SETTINGS, encoding="utf-8")
        analyzer = DjangoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "debug_enabled" in kinds
        assert "hardcoded_secret" in kinds
        assert "allowed_hosts_wildcard" in kinds
        assert "cors_allow_all" in kinds
        assert "csrf_insecure" in kinds
        assert "session_insecure" in kinds
        assert "ssl_redirect_disabled" in kinds
        assert "hsts_disabled" in kinds
        assert "clickjacking_risk" in kinds
        assert "internal_url" in kinds
        assert "mark_safe" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_django_settings_score_well(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(HARDENED_DJANGO_SETTINGS, encoding="utf-8")
        analyzer = DjangoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_settings_returns_empty(self, tmp_path: Path):
        analyzer = DjangoAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no settings" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = DjangoFinding(
            kind="test",
            severity="high",
            message="test message",
            path="settings.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(HARDENED_DJANGO_SETTINGS, encoding="utf-8")
        analyzer = DjangoAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Django settings analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = DjangoAnalyzer(".").generate_hardened_template()
        assert "SECRET_KEY = os.environ" in template
        assert "CORS_ORIGIN_ALLOW_ALL = False" in template

    def test_detects_settings_package(self, tmp_path: Path):
        settings_dir = tmp_path / "settings"
        settings_dir.mkdir()
        (settings_dir / "production.py").write_text("DEBUG = True\n", encoding="utf-8")
        analyzer = DjangoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "debug_enabled" for f in findings)
