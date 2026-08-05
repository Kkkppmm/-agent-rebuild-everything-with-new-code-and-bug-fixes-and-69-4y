"""Tests for v6.13.0 security analyzers."""

from pathlib import Path

from devai import SecurityScanner, SensitiveLoggingAnalyzer


class TestSensitiveLoggingAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def greet(name):\n"
            "    logger.info('hello %s', name)\n",
            encoding="utf-8",
        )
        assert SensitiveLoggingAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_password_logged(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def login(password):\n"
            "    logger.info(password)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_variable_logged" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_token_in_fstring(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            "def debug(access_token):\n"
            "    print(f'using token {access_token}')\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_fstring_logged" for f in findings)

    def test_detects_sensitive_literal(self, tmp_path: Path):
        (tmp_path / "debug.py").write_text(
            "import logging\n"
            "logging.error('password reset failed')\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_literal_in_log" for f in findings)

    def test_skips_test_files(self, tmp_path: Path):
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_auth.py").write_text(
            "def test_login():\n"
            "    print(password)\n",
            encoding="utf-8",
        )
        assert SensitiveLoggingAnalyzer(str(tmp_path)).analyze() == []


class TestSensitiveLoggingScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def reset(secret):\n"
            "    logger.debug(secret)\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("sensitive_logging",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "sensitive_logging" for cat in report.categories)
