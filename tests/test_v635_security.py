"""Tests for v6.35.0 security analyzers."""

from pathlib import Path

from devai import (
    InsecureGraphqlSettingsAnalyzer,
    InsecureJwtSettingsAnalyzer,
    InsecureWebhookSettingsAnalyzer,
    SecurityScanner,
)


class TestInsecureJwtSettingsAnalyzer:
    def test_clean_jwt_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')\n"
            "JWT_ALGORITHM = 'HS256'\n"
            "JWT_VERIFY = True\n"
            "ACCESS_TOKEN_LIFETIME = timedelta(days=1)\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_algorithm_none(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "JWT_ALGORITHM = 'none'\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "jwt_algorithm_none" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_verify_disabled(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "JWT_VERIFY = False\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "jwt_verify_disabled" for f in findings)

    def test_detects_hardcoded_secret(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_SECRET_KEY = 'supersecretkey123'\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_jwt_secret" for f in findings)

    def test_detects_long_expiration(self, tmp_path: Path):
        (tmp_path / "prod.py").write_text(
            "ACCESS_TOKEN_LIFETIME = timedelta(days=90)\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "jwt_long_expiration" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_ALGORITHM = 'none'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_jwt_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_jwt_settings" for cat in report.categories)


class TestInsecureWebhookSettingsAnalyzer:
    def test_clean_webhook_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "WEBHOOK_URL = 'https://api.example.com/webhooks'\n"
            "STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')\n"
            "WEBHOOK_VERIFY_SIGNATURE = True\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_http_webhook_url(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "WEBHOOK_URL = 'http://api.example.com/webhooks'\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "http_webhook_url" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_verify_disabled(self, tmp_path: Path):
        (tmp_path / "webhooks.py").write_text(
            "WEBHOOK_VERIFY_SIGNATURE = False\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "webhook_verify_disabled" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_empty_secret(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "WEBHOOK_SECRET = ''\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "empty_webhook_secret" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "WEBHOOK_VERIFY_SIGNATURE = False\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_webhook_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_webhook_settings" for cat in report.categories)


class TestInsecureGraphqlSettingsAnalyzer:
    def test_clean_graphql_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "GRAPHENE_SCHEMA_INTROSPECTION = False\n"
            "DISABLE_INTROSPECTION = True\n"
            "GRAPHQL_PLAYGROUND = False\n"
            "GRAPHQL_DEBUG = False\n"
            "GRAPHQL_DEPTH_LIMIT = 10\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_introspection_enabled(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "GRAPHQL_INTROSPECTION = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "introspection_enabled" for f in findings)

    def test_detects_playground_enabled(self, tmp_path: Path):
        (tmp_path / "graphql.py").write_text(
            "GRAPHQL_PLAYGROUND = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "playground_enabled" for f in findings)

    def test_detects_debug_enabled(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "GRAPHQL_DEBUG = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "graphql_debug_enabled" for f in findings)

    def test_detects_no_depth_limit(self, tmp_path: Path):
        (tmp_path / "prod.py").write_text(
            "GRAPHQL_DEPTH_LIMIT = None\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "no_depth_limit" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "GRAPHQL_PLAYGROUND = True\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_graphql_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_graphql_settings" for cat in report.categories)
