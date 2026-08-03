"""Tests for LogInjectionAnalyzer."""

from pathlib import Path

from devai.log_injection import LogInjectionAnalyzer

SAFE_CODE = '''
import logging

logger = logging.getLogger(__name__)

def handle(user_id: str):
    logger.info("User logged in", extra={"user_id": user_id})
'''

RISKY_CODE = '''
import logging

logger = logging.getLogger(__name__)

def handle(user_input: str):
    logger.info(f"User action: {user_input}")
    logger.error("Failed for user: " + user_input)
'''


class TestLogInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = LogInjectionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_dynamic_logs(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = LogInjectionAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = LogInjectionAnalyzer(str(tmp_path))
        assert "Log injection" in analyzer.summary()
        assert "Log injection analysis:" in analyzer.to_context()
