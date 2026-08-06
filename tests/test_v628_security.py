"""Tests for v6.28.0 security analyzers."""

from pathlib import Path

from devai import InsecureLoggingSettingsAnalyzer, SecurityScanner


class TestInsecureLoggingSettingsAnalyzer:
    def test_clean_logging_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "DEBUG = False\n"
            "LOGGING = {\n"
            "    'version': 1,\n"
            "    'handlers': {\n"
            "        'file': {'class': 'logging.handlers.RotatingFileHandler'},\n"
            "    },\n"
            "    'loggers': {'django': {'level': 'INFO'}},\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_debug_in_production(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "debug_in_production" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_console_handler(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "LOGGING = {\n"
            "    'handlers': {\n"
            "        'console': {'class': 'logging.StreamHandler'},\n"
            "    },\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "console_log_handler" for f in findings)

    def test_detects_debug_log_level(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "LOGGING = {\n"
            "    'loggers': {'app': {'level': 'DEBUG'}},\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "debug_log_level" for f in findings)

    def test_detects_sensitive_log_format(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "LOGGING = {\n"
            "    'formatters': {\n"
            "        'verbose': {'format': '%(levelname)s %(password)s %(message)s'},\n"
            "    },\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_log_format" for f in findings)

    def test_debug_ok_in_test_file(self, tmp_path: Path):
        (tmp_path / "test_settings.py").write_text("DEBUG = True\n", encoding="utf-8")
        findings = InsecureLoggingSettingsAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "debug_in_production" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")
        report = SecurityScanner(str(tmp_path), checks=("insecure_logging_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_logging_settings" for cat in report.categories)
