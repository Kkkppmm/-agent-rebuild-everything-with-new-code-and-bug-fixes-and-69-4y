"""Tests for HostHeaderAnalyzer."""

from pathlib import Path

from devai.host_header import HostHeaderAnalyzer


SAFE_CODE = '''
def logout():
    return redirect("/login")
'''

RISKY_CODE = '''
from flask import redirect, request

def password_reset():
    url = "https://" + request.host + "/reset"
    return redirect(url)
'''


class TestHostHeaderAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "routes.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = HostHeaderAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HostHeaderAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "host_in_concat" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HostHeaderAnalyzer(str(tmp_path))
        assert "Host header" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
