"""Tests for v6.36.0 security analyzers."""

from pathlib import Path

from devai import InsecureSentrySettingsAnalyzer, SecurityScanner


class TestInsecureSentrySettingsAnalyzer:
    def test_clean_sentry_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "import os\n"
            "import sentry_sdk\n\n"
            "sentry_sdk.init(\n"
            "    dsn=os.environ['SENTRY_DSN'],\n"
            "    send_default_pii=False,\n"
            "    traces_sample_rate=0.1,\n"
            ")\n",
            encoding="utf-8",
        )
        findings = InsecureSentrySettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_send_default_pii(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "import sentry_sdk\n\n"
            "sentry_sdk.init(dsn='https://abc@o123.ingest.sentry.io/456', send_default_pii=True)\n",
            encoding="utf-8",
        )
        findings = InsecureSentrySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "send_default_pii_enabled" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_hardcoded_dsn(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SENTRY_DSN = 'https://abc123@o456.ingest.sentry.io/789'\n",
            encoding="utf-8",
        )
        findings = InsecureSentrySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_sentry_dsn" for f in findings)

    def test_detects_sentry_debug(self, tmp_path: Path):
        (tmp_path / "prod.py").write_text(
            "import sentry_sdk\n\n"
            "sentry_sdk.init(dsn='https://x@o1.ingest.sentry.io/1', debug=True)\n",
            encoding="utf-8",
        )
        findings = InsecureSentrySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sentry_debug_enabled" for f in findings)

    def test_detects_full_sample_rate(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "import sentry_sdk\n\n"
            "sentry_sdk.init(\n"
            "    dsn='https://x@o1.ingest.sentry.io/1',\n"
            "    traces_sample_rate=1.0,\n"
            "    profiles_sample_rate=1,\n"
            ")\n",
            encoding="utf-8",
        )
        findings = InsecureSentrySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "full_sentry_sample_rate" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "import sentry_sdk\n"
            "sentry_sdk.init(send_default_pii=True, dsn='https://a@o1.ingest.sentry.io/1')\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_sentry_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_sentry_settings" for cat in report.categories)
