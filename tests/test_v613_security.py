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

    def test_detects_password_in_fstring_log(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def login(password):\n"
            "    logger.info(f'password={password}')\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_data_logged" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_token_in_print(self, tmp_path: Path):
        (tmp_path / "debug.py").write_text(
            "def show(token):\n"
            "    print(token)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_data_logged" for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_detects_secret_literal_in_log(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def call(api_key):\n"
            "    logger.debug('api_key=%s', api_key)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_data_logged" for f in findings)

    def test_skips_test_files(self, tmp_path: Path):
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_auth.py").write_text(
            "def test_login():\n"
            "    print(password)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_sensitive_keyword_arg(self, tmp_path: Path):
        (tmp_path / "session.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def store(session_token):\n"
            "    logger.info('stored', extra={'session_token': session_token})\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_data_logged" for f in findings)


class TestSensitiveLoggingScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def leak(secret):\n"
            "    logger.error(f'secret={secret}')\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("sensitive_logging",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "sensitive_logging" for cat in report.categories)
