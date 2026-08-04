"""Tests for LogInjectionAnalyzer."""

from pathlib import Path

from devai.log_injection import LogInjectionAnalyzer

SAFE_CODE = '''
import logging

logger = logging.getLogger(__name__)

def greet(user: str) -> None:
    logger.info("User logged in", extra={"user": user})
'''

RISKY_CODE = '''
import logging

logger = logging.getLogger(__name__)

def greet(user: str) -> None:
    logger.info(f"User logged in: {user}")
    logger.error("Failed for %s", user)
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
        assert len(findings) >= 2
        assert analyzer.health_score() < 100.0

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = LogInjectionAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = LogInjectionAnalyzer(str(tmp_path))
        assert "Log injection:" in analyzer.summary()
        assert "Log injection analysis:" in analyzer.to_context()
