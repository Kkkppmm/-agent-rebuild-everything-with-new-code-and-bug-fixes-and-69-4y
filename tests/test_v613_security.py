"""Tests for v6.13.0 security analyzers."""

from pathlib import Path

from devai import SecurityScanner, SensitiveLoggingAnalyzer


class TestSensitiveLoggingAnalyzer:
    def test_clean_code_no_sensitive_logs(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def greet(name):\n"
            "    logger.info('hello %s', name)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_password_in_logger(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def login(user, password):\n"
            "    logger.info(f'login attempt password={password}')\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_value_logged" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_token_in_print(self, tmp_path: Path):
        (tmp_path / "debug.py").write_text(
            "def show(access_token):\n"
            "    print(access_token)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.severity == "critical" for f in findings)
        assert any(f.sink == "print" for f in findings)

    def test_detects_api_key_keyword_arg(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def configure(api_key):\n"
            "    logger.debug('key', api_key=api_key)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_kwarg_logged" for f in findings)

    def test_skips_test_files(self, tmp_path: Path):
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_auth.py").write_text(
            "def test_login():\n"
            "    print('password123')\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert not findings


class TestSensitiveLoggingScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def reset(password):\n"
            "    logger.error(password)\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("sensitive_logging",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "sensitive_logging" for cat in report.categories)
