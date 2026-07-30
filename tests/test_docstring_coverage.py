"""Tests for DevAI DocstringCoverage."""

from pathlib import Path

from devai.docstring_coverage import DocstringCoverage, DocstringGap


DOCUMENTED = '''
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
'''

UNDOCUMENTED = """
def process(data):
    return data
"""

CLASS_SAMPLE = '''
class Service:
    """A service class."""

    def run(self, x: int) -> int:
        """Run the service."""
        return x

    def helper(self, y):
        return y
'''


class TestDocstringCoverage:
    def test_fully_documented(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(DOCUMENTED, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert gaps == []
        assert coverage.coverage_pct() == 100.0

    def test_detects_missing_docstrings(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(UNDOCUMENTED, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert len(gaps) == 1
        assert gaps[0].name == "process"

    def test_class_methods(self, tmp_path: Path):
        (tmp_path / "svc.py").write_text(CLASS_SAMPLE, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert any(g.name == "Service.helper" for g in gaps)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(UNDOCUMENTED, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        assert "Docstring coverage:" in coverage.summary()
        context = coverage.to_context()
        assert "process" in context

    def test_docstring_gap_format(self):
        gap = DocstringGap(path="app.py", name="foo", lineno=1, kind="function")
        assert "foo" in gap.format()
        assert "docstring" in gap.format()
