"""Tests for v6.23.0 security analyzers."""

from pathlib import Path

from devai import InsecureSessionSettingsAnalyzer, SecurityScanner


class TestInsecureSessionSettingsAnalyzer:
    def test_clean_secure_session_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SESSION_COOKIE_SECURE = True\n"
            "SESSION_COOKIE_HTTPONLY = True\n"
            "SESSION_COOKIE_SAMESITE = 'Lax'\n",
            encoding="utf-8",
        )
        findings = InsecureSessionSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_session_cookie_secure_false(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SESSION_COOKIE_SECURE = False\n",
            encoding="utf-8",
        )
        findings = InsecureSessionSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_session_cookie_secure" for f in findings)
        assert any(f.severity == "high" for f in findings)
        assert any(f.setting == "SESSION_COOKIE_SECURE" for f in findings)

    def test_detects_session_cookie_httponly_false(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SESSION_COOKIE_HTTPONLY = False\n",
            encoding="utf-8",
        )
        findings = InsecureSessionSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_session_cookie_httponly" for f in findings)

    def test_detects_csrf_cookie_secure_false(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CSRF_COOKIE_SECURE = False\n",
            encoding="utf-8",
        )
        findings = InsecureSessionSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_csrf_cookie_secure" for f in findings)

    def test_detects_disabled_samesite(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SESSION_COOKIE_SAMESITE = None\n",
            encoding="utf-8",
        )
        findings = InsecureSessionSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_session_cookie_samesite" for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SESSION_COOKIE_SECURE = False\n",
            encoding="utf-8",
        )
        report = SecurityScanner(
            str(tmp_path), checks=("insecure_session_settings",)
        ).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_session_settings" for cat in report.categories)
