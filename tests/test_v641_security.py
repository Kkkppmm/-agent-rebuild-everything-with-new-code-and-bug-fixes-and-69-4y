"""Tests for v6.41.0 security analyzers."""

from pathlib import Path

from devai import (
    InsecureElasticsearchSettingsAnalyzer,
    InsecureOAuthSettingsAnalyzer,
    InsecureSwaggerSettingsAnalyzer,
    SecurityScanner,
)


class TestInsecureOAuthSettingsAnalyzer:
    def test_clean_oauth_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "OAUTH_PKCE_REQUIRED = True\n"
            "OAUTH_STATE_ENABLED = True\n"
            "OAUTH_CLIENT_SECRET = os.environ['OAUTH_CLIENT_SECRET']\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_pkce_disabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "OAUTH_PKCE_REQUIRED = False\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "oauth_pkce_disabled" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_state_disabled(self, tmp_path: Path):
        (tmp_path / "oauth.py").write_text(
            "OAUTH_STATE_ENABLED = False\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "oauth_state_disabled" for f in findings)

    def test_detects_hardcoded_client_secret(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "OAUTH_CLIENT_SECRET = 'super-secret-oauth-key'\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_oauth_client_secret" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_insecure_transport(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "OAUTHLIB_INSECURE_TRANSPORT = '1'\n",
            encoding="utf-8",
        )
        findings = InsecureOAuthSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "oauth_insecure_transport" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "OAUTH_PKCE_REQUIRED = False\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_oauth_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_oauth_settings" for cat in report.categories)


class TestInsecureSwaggerSettingsAnalyzer:
    def test_clean_swagger_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SPECTACULAR_SETTINGS = {'SERVE_PUBLIC': False}\n"
            "SWAGGER_UI_ENABLED = False\n",
            encoding="utf-8",
        )
        findings = InsecureSwaggerSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_serve_public(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SPECTACULAR_SETTINGS = {'SERVE_PUBLIC': True}\n",
            encoding="utf-8",
        )
        findings = InsecureSwaggerSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "swagger_public_access" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_swagger_ui_enabled(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "SWAGGER_UI_ENABLED = True\n",
            encoding="utf-8",
        )
        findings = InsecureSwaggerSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "swagger_ui_enabled" for f in findings)

    def test_detects_drf_yasg_enabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "DRF_YASG_ENABLED = True\n",
            encoding="utf-8",
        )
        findings = InsecureSwaggerSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "swagger_ui_enabled" for f in findings)

    def test_detects_swagger_url(self, tmp_path: Path):
        (tmp_path / "urls.py").write_text(
            "urlpatterns = [path('swagger/', schema_view)]\n",
            encoding="utf-8",
        )
        findings = InsecureSwaggerSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "swagger_url_exposed" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SPECTACULAR_SETTINGS = {'SERVE_PUBLIC': True}\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_swagger_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_swagger_settings" for cat in report.categories)


class TestInsecureElasticsearchSettingsAnalyzer:
    def test_clean_elasticsearch_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ELASTICSEARCH_URL = os.environ['ELASTICSEARCH_URL']\n"
            "ELASTICSEARCH_VERIFY_CERTS = True\n",
            encoding="utf-8",
        )
        findings = InsecureElasticsearchSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_no_auth_url(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ELASTICSEARCH_URL = 'elasticsearch://localhost:9200'\n",
            encoding="utf-8",
        )
        findings = InsecureElasticsearchSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "elasticsearch_no_auth" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_plaintext_http(self, tmp_path: Path):
        (tmp_path / "search.py").write_text(
            "ELASTICSEARCH_URL = 'http://elastic.example.com:9200'\n",
            encoding="utf-8",
        )
        findings = InsecureElasticsearchSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "elasticsearch_plaintext" for f in findings)

    def test_detects_verify_certs_disabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ELASTICSEARCH_VERIFY_CERTS = False\n",
            encoding="utf-8",
        )
        findings = InsecureElasticsearchSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "elasticsearch_verify_certs_disabled" for f in findings)

    def test_detects_hardcoded_password(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "ELASTICSEARCH_PASSWORD = 'elastic-password-123'\n",
            encoding="utf-8",
        )
        findings = InsecureElasticsearchSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_elasticsearch_password" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ELASTICSEARCH_VERIFY_CERTS = False\n",
            encoding="utf-8",
        )
        report = SecurityScanner(
            str(tmp_path), checks=("insecure_elasticsearch_settings",)
        ).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_elasticsearch_settings" for cat in report.categories)
