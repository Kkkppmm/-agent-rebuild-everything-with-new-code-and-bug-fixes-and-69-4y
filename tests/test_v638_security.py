"""Tests for v6.38.0 security analyzers."""

from pathlib import Path

from devai import InsecureOAuthSettingsAnalyzer, SecurityScanner


class TestInsecureOAuthSettingsAnalyzer:
    def test_clean_oauth_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.environ['GOOGLE_KEY']\n"
            "SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.environ['GOOGLE_SECRET']\n"
            "ALLOWED_REDIRECT_URIS = ['https://example.com/callback']\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_insecure_transport(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "OAUTHLIB_INSECURE_TRANSPORT = True\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "oauth_insecure_transport" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_hardcoded_client_secret(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'supersecretclientkey123'\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_oauth_secret" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_http_redirect_uri(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ALLOWED_REDIRECT_URIS = ['http://localhost:8000/callback']\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "http_redirect_uri" for f in findings)

    def test_detects_wildcard_redirect_uri(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ALLOWED_REDIRECT_URIS = ['https://*.example.com/callback']\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "wildcard_redirect_uri" for f in findings)

    def test_detects_oidc_client_secret(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "OIDC_RP_CLIENT_SECRET = 'my-oidc-secret-value'\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_oauth_secret" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "OAUTHLIB_INSECURE_TRANSPORT = 1\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_oauth_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_oauth_settings" for cat in report.categories)
