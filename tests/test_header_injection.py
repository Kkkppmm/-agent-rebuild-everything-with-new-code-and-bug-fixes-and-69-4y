"""Tests for HeaderInjectionAnalyzer."""

from pathlib import Path

from devai.header_injection import HeaderInjectionAnalyzer

SAFE_CODE = '''
def handler(request, response):
    response.headers["X-Custom"] = "static-value"
'''

RISKY_CODE = '''
def handler(request, response):
    response.headers["Location"] = request.args.get("url")
    response.set_header("X-User", request.form["name"])
'''


class TestHeaderInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = HeaderInjectionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_headers(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HeaderInjectionAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = HeaderInjectionAnalyzer(str(tmp_path))
        assert "Header injection:" in analyzer.summary()
        assert "Header injection analysis:" in analyzer.to_context()
