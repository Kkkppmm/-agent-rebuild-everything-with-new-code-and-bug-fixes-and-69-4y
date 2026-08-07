"""Tests for v6.24.0 security analyzers."""

from pathlib import Path

from devai import InsecureTransportSettingsAnalyzer, SecurityScanner


class TestInsecureTransportSettingsAnalyzer:
    def test_clean_secure_transport_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECURE_SSL_REDIRECT = True\n"
            "SECURE_HSTS_SECONDS = 31536000\n"
            "SECURE_CONTENT_TYPE_NOSNIFF = True\n"
            "PREFERRED_URL_SCHEME = 'https'\n",
            encoding="utf-8",
        )
        findings = InsecureTransportSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_ssl_redirect_false(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECURE_SSL_REDIRECT = False\n",
            encoding="utf-8",
        )
        findings = InsecureTransportSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_secure_ssl_redirect" for f in findings)
        assert any(f.severity == "high" for f in findings)
        assert any(f.setting == "SECURE_SSL_REDIRECT" for f in findings)

    def test_detects_hsts_disabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECURE_HSTS_SECONDS = 0\n",
            encoding="utf-8",
        )
        findings = InsecureTransportSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_secure_hsts_seconds" for f in findings)

    def test_detects_content_type_nosniff_false(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECURE_CONTENT_TYPE_NOSNIFF = False\n",
            encoding="utf-8",
        )
        findings = InsecureTransportSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_secure_content_type_nosniff" for f in findings)

    def test_detects_insecure_url_scheme(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "PREFERRED_URL_SCHEME = 'http'\n",
            encoding="utf-8",
        )
        findings = InsecureTransportSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_preferred_url_scheme" for f in findings)

    def test_detects_disabled_proxy_ssl_header(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECURE_PROXY_SSL_HEADER = None\n",
            encoding="utf-8",
        )
        findings = InsecureTransportSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "insecure_secure_proxy_ssl_header" for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECURE_SSL_REDIRECT = False\n",
            encoding="utf-8",
        )
        report = SecurityScanner(
            str(tmp_path), checks=("insecure_transport_settings",)
        ).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_transport_settings" for cat in report.categories)
