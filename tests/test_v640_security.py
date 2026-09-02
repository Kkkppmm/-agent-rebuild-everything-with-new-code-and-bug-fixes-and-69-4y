"""Tests for v6.40.0 security analyzers."""

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
            "GRAPHQL_INTROSPECTION = False\n"
            "GRAPHQL_PLAYGROUND_ENABLED = False\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_introspection_enabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "GRAPHQL_INTROSPECTION = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "graphql_introspection_enabled" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_playground_enabled(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "GRAPHQL_PLAYGROUND_ENABLED = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "graphql_playground_enabled" for f in findings)

    def test_detects_graphiql_enabled(self, tmp_path: Path):
        (tmp_path / "graphql.py").write_text(
            "GRAPHIQL_ENABLED = True\n",
            encoding="utf-8",
        )
        findings = InsecureGraphqlSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "graphql_playground_enabled" for f in findings)

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
            "VERIFY_WEBHOOK_SIGNATURE = True\n"
            "WEBHOOK_SECRET = os.environ['WEBHOOK_SECRET']\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_signature_verification_disabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "VERIFY_WEBHOOK_SIGNATURE = False\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "webhook_signature_verification_disabled" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_skip_verify(self, tmp_path: Path):
        (tmp_path / "webhooks.py").write_text(
            "WEBHOOK_SKIP_VERIFY = True\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "webhook_signature_verification_disabled" for f in findings)

    def test_detects_empty_webhook_secret(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "STRIPE_WEBHOOK_SECRET = ''\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "empty_webhook_secret" for f in findings)

    def test_detects_weak_webhook_secret(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "WEBHOOK_SECRET = 'short'\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_webhook_secret" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "VERIFY_WEBHOOK_SIGNATURE = False\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_webhook_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_webhook_settings" for cat in report.categories)


class TestInsecureJwtSettingsAnalyzer:
    def test_clean_jwt_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_VERIFY = True\n"
            "JWT_ALGORITHM = 'HS256'\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_jwt_verify_disabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_VERIFY = False\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "jwt_verification_disabled" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_jwt_algorithm_none(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "JWT_ALGORITHM = 'none'\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "jwt_algorithm_none" for f in findings)

    def test_detects_weak_jwt_secret(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_SECRET_KEY = 'too-short-secret'\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_jwt_secret" for f in findings)

    def test_detects_simple_jwt_verify_false(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SIMPLE_JWT = {'VERIFY': False}\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "jwt_verification_disabled" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_VERIFY = False\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_jwt_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_jwt_settings" for cat in report.categories)
