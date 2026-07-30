"""Tests for DevAI DevTools facade."""

from pathlib import Path

from devai import DevTools, DevToolsReport


SAMPLE_MODULE = '''
"""Sample module."""

def add(a: int, b: int) -> int:
    return a + b

def undocumented():
    pass
'''

SECRET_SAMPLE = 'API_KEY = "sk-1234567890abcdefghijklmnopqrstuv"\n'


class TestDevTools:
    def test_imports_property(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAMPLE_MODULE, encoding="utf-8")
        tools = DevTools(tmp_path)
        assert tools.imports is tools.imports

    def test_analyze_all(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAMPLE_MODULE, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("httpx>=0.27.0\n", encoding="utf-8")
        report = DevTools(tmp_path).analyze_all()
        assert isinstance(report, DevToolsReport)
        assert report.root == str(tmp_path.resolve())
        assert "Typing coverage:" in report.typing
        assert "Docstring coverage:" in report.docstrings

    def test_summary(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAMPLE_MODULE, encoding="utf-8")
        summary = DevTools(tmp_path).summary()
        assert "DevTools report" in summary
        assert "Imports" in summary

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAMPLE_MODULE, encoding="utf-8")
        report = DevTools(tmp_path).analyze_all()
        context = report.to_context()
        assert "Static analysis" in context

    def test_scan_secrets(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(SECRET_SAMPLE, encoding="utf-8")
        findings = DevTools(tmp_path).scan_secrets()
        assert len(findings) >= 1

    def test_typing_stats(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAMPLE_MODULE, encoding="utf-8")
        stats = DevTools(tmp_path).typing_stats()
        assert stats.total_functions >= 1

    def test_docstring_stats(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAMPLE_MODULE, encoding="utf-8")
        stats = DevTools(tmp_path).docstring_stats()
        assert stats.total_items >= 1

    def test_list_dependencies(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("httpx>=0.27.0\n", encoding="utf-8")
        deps = DevTools(tmp_path).list_dependencies()
        assert any(d.name == "httpx" for d in deps)
