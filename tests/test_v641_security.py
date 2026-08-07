"""Tests for v6.41.0 security analyzers."""

from pathlib import Path

from devai import InsecureWebhookSettingsAnalyzer, SecurityScanner


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
            "STRIPE_WEBHOOK_SECRET = 'whsec_abcdefghijklmnop'\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_webhook_secret" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_skip_signature_verification(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "WEBHOOK_SIGNATURE_VERIFICATION = False\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "skip_signature_verification" for f in findings)

    def test_detects_http_webhook_url(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "WEBHOOK_URL = 'http://api.example.com/webhooks'\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "http_webhook_url" for f in findings)

    def test_detects_csrf_exempt_webhook(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "@csrf_exempt\ndef stripe_webhook(request):\n    pass\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "csrf_exempt_webhook" for f in findings)

    def test_detects_verify_false_in_handler(self, tmp_path: Path):
        (tmp_path / "webhooks.py").write_text(
            "event = stripe.Webhook.construct_event(payload, sig, secret, verify=False)\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "skip_signature_verification" for f in findings)

    def test_detects_unauthenticated_webhook_route(self, tmp_path: Path):
        (tmp_path / "urls.py").write_text(
            "path('webhook', WebhookView.as_view(permission_classes=[AllowAny]))\n",
            encoding="utf-8",
        )
        findings = InsecureWebhookSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unauthenticated_webhook" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "WEBHOOK_SECRET = 'hardcoded_secret_value'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_webhook_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_webhook_settings" for cat in report.categories)
