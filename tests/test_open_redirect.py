"""Tests for OpenRedirectAnalyzer."""

from pathlib import Path

from devai.open_redirect import OpenRedirectAnalyzer


class TestOpenRedirectAnalyzer:
    def test_clean_project(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("def home(): return 'ok'\n", encoding="utf-8")

        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_flask_redirect(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "def login():\n    next_url = request.args.get('next')\n"
            "    return redirect(next_url)\n",
            encoding="utf-8",
        )
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert any(f.pattern == "dynamic_redirect" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def foo(): return 1\n", encoding="utf-8")
        analyzer = OpenRedirectAnalyzer(str(tmp_path))
        assert "Open redirect" in analyzer.summary()
        assert "Open redirect analysis:" in analyzer.to_context()
