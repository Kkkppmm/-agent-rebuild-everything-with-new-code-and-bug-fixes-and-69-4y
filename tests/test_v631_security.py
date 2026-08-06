"""Tests for v6.31.0 security analyzers."""

from pathlib import Path

from devai import InsecureAuthSettingsAnalyzer, SecurityScanner


class TestInsecureAuthSettingsAnalyzer:
    def test_clean_auth_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "PASSWORD_HASHERS = [\n"
            "    'django.contrib.auth.hashers.Argon2PasswordHasher',\n"
            "]\n"
            "AUTH_PASSWORD_VALIDATORS = [\n"
            "    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},\n"
            "]\n"
            "AUTHENTICATION_BACKENDS = [\n"
            "    'django.contrib.auth.backends.ModelBackend',\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_weak_password_hasher(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "PASSWORD_HASHERS = [\n"
            "    'django.contrib.auth.hashers.MD5PasswordHasher',\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_password_hasher" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_empty_password_validators(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "AUTH_PASSWORD_VALIDATORS = []\n",
            encoding="utf-8",
        )
        findings = InsecureAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "empty_password_validators" for f in findings)

    def test_detects_allow_all_users_backend(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "AUTHENTICATION_BACKENDS = [\n"
            "    'django.contrib.auth.backends.AllowAllUsersModelBackend',\n"
            "]\n",
            encoding="utf-8",
        )
        findings = InsecureAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "allow_all_users_backend" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_ldap_without_tls(self, tmp_path: Path):
        (tmp_path / "ldap.py").write_text(
            "AUTH_LDAP_SERVER_URI = 'ldap://ldap.example.com'\n",
            encoding="utf-8",
        )
        findings = InsecureAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "ldap_without_tls" for f in findings)

    def test_ldap_with_start_tls_is_clean(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "AUTH_LDAP_SERVER_URI = 'ldap://ldap.example.com'\n"
            "AUTH_LDAP_START_TLS = True\n",
            encoding="utf-8",
        )
        findings = InsecureAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "ldap_without_tls" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "AUTHENTICATION_BACKENDS = [\n"
            "    'django.contrib.auth.backends.AllowAllUsersModelBackend',\n"
            "]\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_auth_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_auth_settings" for cat in report.categories)
