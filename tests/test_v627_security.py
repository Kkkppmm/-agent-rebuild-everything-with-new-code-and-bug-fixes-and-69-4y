"""Tests for v6.27.0 security analyzers."""

from pathlib import Path

from devai import InsecureEmailSettingsAnalyzer, SecurityScanner


class TestInsecureEmailSettingsAnalyzer:
    def test_clean_email_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'\n"
            "EMAIL_HOST = 'smtp.example.com'\n"
            "EMAIL_PORT = 587\n"
            "EMAIL_USE_TLS = True\n"
            "EMAIL_HOST_PASSWORD = os.environ['SMTP_PASSWORD']\n",
            encoding="utf-8",
        )
        findings = InsecureEmailSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_console_backend_in_production(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'\n",
            encoding="utf-8",
        )
        findings = InsecureEmailSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "console_email_in_production" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_empty_smtp_password(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'\n"
            "EMAIL_HOST_PASSWORD = ''\n",
            encoding="utf-8",
        )
        findings = InsecureEmailSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "empty_email_password" for f in findings)

    def test_detects_tls_disabled_with_smtp(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'\n"
            "EMAIL_USE_TLS = False\n"
            "EMAIL_USE_SSL = False\n",
            encoding="utf-8",
        )
        findings = InsecureEmailSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "smtp_tls_disabled" for f in findings)

    def test_detects_file_backend_in_production(self, tmp_path: Path):
        (tmp_path / "prod.py").write_text(
            "EMAIL_BACKEND = 'django.core.mail.backends.filebased.EmailBackend'\n",
            encoding="utf-8",
        )
        findings = InsecureEmailSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "file_email_in_production" for f in findings)

    def test_console_ok_in_test_file(self, tmp_path: Path):
        (tmp_path / "test_email.py").write_text(
            "EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'\n",
            encoding="utf-8",
        )
        findings = InsecureEmailSettingsAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "console_email_in_production" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_email_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_email_settings" for cat in report.categories)
