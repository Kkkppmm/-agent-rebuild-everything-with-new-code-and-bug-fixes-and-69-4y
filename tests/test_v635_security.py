"""Tests for v6.35.0 security analyzers."""

from pathlib import Path

from devai import (
    InsecureGraphqlSettingsAnalyzer,
    InsecureJwtSettingsAnalyzer,
    InsecureWebhookSettingsAnalyzer,
    SecurityScanner,
)


class TestInsecureGraphqlSettingsAnalyzer:
    def test_clean_graphql_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "GRAPHENE = {'SCHEMA': 'app.schema.schema'}\n"
            "GRAPHQL_INTROSPECTION = False\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_graphql_playground(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "GRAPHQL_PLAYGROUND = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "graphql_playground_enabled" for f in findings)

    def test_detects_introspection_enabled(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "GRAPHQL_INTROSPECTION = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "introspection_enabled" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_empty_graphene_middleware(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "GRAPHENE = {'MIDDLEWARE': []}\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "empty_graphene_middleware" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "GRAPHQL_INTROSPECTION = True\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_graphql_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_graphql_settings" for cat in report.categories)


class TestInsecureWebhookSettingsAnalyzer:
    def test_clean_webhook_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "WEBHOOK_VERIFY = True\n"
            "WEBHOOK_URL = 'https://api.example.com/webhooks'\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_hardcoded_webhook_secret(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "WEBHOOK_SECRET = 'whsec_hardcoded_secret_key_12345'\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_webhook_secret" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_webhook_verify_disabled(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "VERIFY_WEBHOOK = False\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "webhook_verify_disabled" for f in findings)

    def test_detects_http_webhook_url(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "WEBHOOK_URL = 'http://internal.example.com/hook'\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "http_webhook_url" for f in findings)

    def test_detects_csrf_exempt_webhook(self, tmp_path: Path):
        (tmp_path / "webhooks.py").write_text(
            "from django.views.decorators.csrf import csrf_exempt\n\n"
            "@csrf_exempt\n"
            "def stripe_webhook(request):\n"
            "    pass\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "csrf_exempt_webhook_handler" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "VERIFY_WEBHOOK = False\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_webhook_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_webhook_settings" for cat in report.categories)


class TestInsecureJwtSettingsAnalyzer:
    def test_clean_jwt_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SIMPLE_JWT = {\n"
            "    'SIGNING_KEY': os.environ['JWT_SECRET'],\n"
            "    'ALGORITHM': 'HS256',\n"
            "    'VERIFY': True,\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_hardcoded_jwt_secret(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_SECRET_KEY = 'super_secret_jwt_key_12345'\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_jwt_secret" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_none_algorithm(self, tmp_path: Path):
        (tmp_path / "jwt.py").write_text(
            "JWT_ALGORITHM = 'none'\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "none_jwt_algorithm" for f in findings)

    def test_detects_jwt_verify_disabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_VERIFY = False\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "jwt_verify_disabled" for f in findings)

    def test_detects_jwt_in_query_string(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "def auth_view(request):\n"
            "    token = request.GET.get('token')\n"
            "    return token\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "jwt_in_query_string" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_VERIFY = False\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_jwt_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_jwt_settings" for cat in report.categories)
