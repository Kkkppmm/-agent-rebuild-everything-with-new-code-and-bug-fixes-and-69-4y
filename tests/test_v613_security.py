"""Tests for v6.13.0 security analyzers."""

from pathlib import Path

from devai import SecurityScanner, SensitiveLoggingAnalyzer


class TestSensitiveLoggingAnalyzer:
    def test_clean_code_no_sensitive_logging(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def greet(name):\n"
            "    logger.info('hello %s', name)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_direct_password_log(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def login(password):\n"
            "    logger.info(password)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_arg" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_fstring_token_log(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def debug_token(token):\n"
            "    logger.debug(f'token={token}')\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_fstring" for f in findings)

    def test_detects_format_arg_secret(self, tmp_path: Path):
        (tmp_path / "svc.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def save(api_key):\n"
            "    logger.info('key: %s', api_key)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_format_arg" for f in findings)

    def test_detects_print_secret(self, tmp_path: Path):
        (tmp_path / "debug.py").write_text(
            "def show(secret):\n"
            "    print(secret)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sensitive_arg" for f in findings)

    def test_allows_safe_logging(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def process(user_id):\n"
            "    logger.info('processing user %s', user_id)\n",
            encoding="utf-8",
        )
        findings = SensitiveLoggingAnalyzer(str(tmp_path)).analyze()
        assert not findings


class TestSensitiveLoggingScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def handler(token):\n"
            "    logger.info(token)\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("sensitive_logging",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "sensitive_logging" for cat in report.categories)
