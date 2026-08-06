"""Tests for v6.28.0 security analyzers."""

from pathlib import Path

from devai import InsecureLoggingSettingsAnalyzer, SecurityScanner


class TestInsecureLoggingSettingsAnalyzer:
    def test_clean_logging_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "LOG_LEVEL = 'INFO'\n"
            "LOGGING = {\n"
            "    'version': 1,\n"
            "    'handlers': {\n"
            "        'file': {'class': 'logging.FileHandler', 'filename': '/var/log/app.log'},\n"
            "    },\n"
            "    'root': {'handlers': ['file'], 'level': 'INFO'},\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_debug_level_in_production(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "LOG_LEVEL = 'DEBUG'\n",
            encoding="utf-8",
        )
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "debug_logging_in_production" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_console_handler_in_production(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "LOGGING = {\n"
            "    'handlers': {\n"
            "        'console': {'class': 'logging.StreamHandler'},\n"
            "    },\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "console_handler_in_production" for f in findings)

    def test_detects_sensitive_log_format(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "LOGGING = {\n"
            "    'handlers': {\n"
            "        'file': {\n"
            "            'class': 'logging.FileHandler',\n"
            "            'formatter': '%(levelname)s user=%(name)s password=%(password)s',\n"
            "        },\n"
            "    },\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_log_format" for f in findings)

    def test_debug_ok_in_test_file(self, tmp_path: Path):
        (tmp_path / "test_logging.py").write_text(
            "LOG_LEVEL = 'DEBUG'\n",
            encoding="utf-8",
        )
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "debug_logging_in_production" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "LOG_LEVEL = 'DEBUG'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_logging_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_logging_settings" for cat in report.categories)
