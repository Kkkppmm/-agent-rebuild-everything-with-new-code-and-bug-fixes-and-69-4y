"""Tests for v6.43.0 security analyzers."""

from pathlib import Path

from devai import (
    InsecureS3SettingsAnalyzer,
    InsecureSentrySettingsAnalyzer,
    InsecureStripeSettingsAnalyzer,
    SecurityScanner,
)


class TestInsecureS3SettingsAnalyzer:
    def test_clean_s3_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "AWS_STORAGE_BUCKET_NAME = os.environ['S3_BUCKET']\n"
            "AWS_DEFAULT_ACL = 'private'\n"
            "AWS_S3_SECURE_URLS = True\n",
            encoding="utf-8",
        )
        findings = InsecureS3SettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_hardcoded_credentials(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
            "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n",
            encoding="utf-8",
        )
        findings = InsecureS3SettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_aws_credentials" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_public_acl(self, tmp_path: Path):
        (tmp_path / "storage.py").write_text(
            "AWS_DEFAULT_ACL = 'public-read'\n",
            encoding="utf-8",
        )
        findings = InsecureS3SettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "s3_public_acl" for f in findings)

    def test_detects_insecure_endpoint(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "AWS_S3_ENDPOINT_URL = 'http://minio.local:9000'\n",
            encoding="utf-8",
        )
        findings = InsecureS3SettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "s3_insecure_endpoint" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "AWS_DEFAULT_ACL = 'public-read'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_s3_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_s3_settings" for cat in report.categories)


class TestInsecureStripeSettingsAnalyzer:
    def test_clean_stripe_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "STRIPE_SECRET_KEY = os.environ['STRIPE_SECRET_KEY']\n"
            "STRIPE_WEBHOOK_SECRET = os.environ['STRIPE_WEBHOOK_SECRET']\n",
            encoding="utf-8",
        )
        findings = InsecureStripeSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_hardcoded_secret_key(self, tmp_path: Path):
        test_key = "sk_" + "test_" + "51HxYzAbCdEfGhIjKlMnOpQr"
        (tmp_path / "payments.py").write_text(
            f"STRIPE_SECRET_KEY = '{test_key}'\n",
            encoding="utf-8",
        )
        findings = InsecureStripeSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_stripe_secret" for f in findings)

    def test_detects_live_key_as_critical(self, tmp_path: Path):
        live_key = "sk_" + "live_" + "51HxYzAbCdEfGhIjKlMnOpQr"
        (tmp_path / "settings.py").write_text(
            f"STRIPE_SECRET_KEY = '{live_key}'\n",
            encoding="utf-8",
        )
        findings = InsecureStripeSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_stripe_secret" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_hardcoded_webhook_secret(self, tmp_path: Path):
        webhook = "whsec_" + "abc123def456ghi789"
        (tmp_path / "config.py").write_text(
            f"STRIPE_WEBHOOK_SECRET = '{webhook}'\n",
            encoding="utf-8",
        )
        findings = InsecureStripeSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_webhook_secret" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        test_key = "sk_" + "test_" + "abc123"
        (tmp_path / "settings.py").write_text(
            f"STRIPE_SECRET_KEY = '{test_key}'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_stripe_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_stripe_settings" for cat in report.categories)


class TestInsecureSentrySettingsAnalyzer:
    def test_clean_sentry_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SENTRY_DSN = os.environ['SENTRY_DSN']\n"
            "SENTRY_ENVIRONMENT = 'production'\n"
            "SENTRY_SEND_DEFAULT_PII = False\n",
            encoding="utf-8",
        )
        findings = InsecureSentrySettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_hardcoded_dsn(self, tmp_path: Path):
        (tmp_path / "sentry.py").write_text(
            "SENTRY_DSN = 'https://abc123@o123456.ingest.sentry.io/7890123'\n",
            encoding="utf-8",
        )
        findings = InsecureSentrySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_sentry_dsn" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_pii_enabled(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SENTRY_SEND_DEFAULT_PII = True\n",
            encoding="utf-8",
        )
        findings = InsecureSentrySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sentry_pii_enabled" for f in findings)

    def test_detects_dev_environment(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "SENTRY_ENVIRONMENT = 'development'\n",
            encoding="utf-8",
        )
        findings = InsecureSentrySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sentry_dev_environment" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SENTRY_DSN = 'https://key@o123.ingest.sentry.io/1'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_sentry_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_sentry_settings" for cat in report.categories)
