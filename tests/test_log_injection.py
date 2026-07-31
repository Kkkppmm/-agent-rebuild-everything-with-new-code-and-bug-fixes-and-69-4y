"""Tests for LogInjectionAnalyzer."""

from pathlib import Path

from devai.log_injection import LogInjectionAnalyzer

SAFE_CODE = '''
import logging

logger = logging.getLogger(__name__)

def process(user_id: int):
    logger.info("Processing user %s", user_id)
'''

RISKY_CODE = '''
import logging

logger = logging.getLogger(__name__)

def handle_request(request):
    username = request.headers.get("X-User")
    logger.info(f"User login: {username}")
    logger.error("Failed for " + request.path)
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
        assert "Findings:" in analyzer.to_context()
