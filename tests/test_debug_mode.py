"""Tests for DebugModeAnalyzer."""

from pathlib import Path

from devai.debug_mode import DebugModeAnalyzer


SAFE_CODE = '''
import os

DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

def create_app():
    from flask import Flask
    app = Flask(__name__)
    return app
'''

RISKY_CODE = '''
DEBUG = True
FLASK_ENV = "development"

def create_app():
    from flask import Flask
    app = Flask(__name__)
    app.run(debug=True)
    return app
'''


class TestDebugModeAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = DebugModeAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = DebugModeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "debug_flag_true" in patterns
        assert "dev_environment" in patterns
        assert "run_debug_true" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = DebugModeAnalyzer(str(tmp_path))
        assert "Debug mode" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = DebugModeAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 2
