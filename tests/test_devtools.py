"""Tests for DevAI DevTools facade."""

from pathlib import Path

from devai import DevTools, DevToolsReport


SAMPLE_PY = '''\
"""Sample module."""

def typed_fn(x: int) -> str:
    """A typed function."""
    return str(x)

def untyped_fn(x):
  return x
'''


class TestDevTools:
    def test_scan_returns_report(self, tmp_path: Path):
        (tmp_path / "sample.py").write_text(SAMPLE_PY)
        tools = DevTools(str(tmp_path))
        report = tools.scan(secrets=False, deps=False)
        assert isinstance(report, DevToolsReport)
        assert report.root == str(tmp_path.resolve())
        assert "Imports" in report.imports_summary or report.imports_summary
        assert report.typing_summary

    def test_summary(self, tmp_path: Path):
        (tmp_path / "sample.py").write_text(SAMPLE_PY)
        tools = DevTools(str(tmp_path))
        text = tools.summary()
        assert "DevTools report" in text
        assert "Typing" in text

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "sample.py").write_text(SAMPLE_PY)
        tools = DevTools(str(tmp_path))
        ctx = tools.to_context()
        assert "Static analysis" in ctx
        assert "Typing coverage" in ctx

    def test_lazy_properties(self, tmp_path: Path):
        (tmp_path / "sample.py").write_text(SAMPLE_PY)
        tools = DevTools(str(tmp_path))
        assert tools.imports is tools.imports
        assert tools.typing is tools.typing
        assert tools.docstrings is tools.docstrings

    def test_selective_scan(self, tmp_path: Path):
        (tmp_path / "sample.py").write_text(SAMPLE_PY)
        tools = DevTools(str(tmp_path))
        report = tools.scan(imports=False, secrets=False, typing=True, docstrings=False, deps=False)
        assert report.typing_summary
        assert report.imports_summary == ""
        assert report.docstring_summary == ""

    def test_runtime_devtools(self, tmp_path: Path):
        from devai import DevRuntime

        (tmp_path / "sample.py").write_text(SAMPLE_PY)
        runtime = DevRuntime.create(use_mock=True, project_path=tmp_path)
        tools = runtime.devtools()
        assert isinstance(tools, DevTools)
        report = tools.scan(secrets=False, deps=False)
        assert report.typing_summary
