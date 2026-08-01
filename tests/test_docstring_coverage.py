"""Tests for DevAI DocstringCoverage."""

from pathlib import Path

from devai.docstring_coverage import DocstringCoverage, DocstringGap


FULLY_DOCUMENTED = '''
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


class Service:
    """A service class."""

    def run(self, x: int) -> int:
        """Run the service."""
        return x
'''

PARTIALLY_DOCUMENTED = '''
def greet(name: str):
    """Say hello."""
    return f"hi {name}"


def undocumented():
    return 42
'''

UNDOCUMENTED = """
def process(data):
    return data
"""


class TestDocstringCoverage:
    def test_fully_documented(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FULLY_DOCUMENTED, encoding="utf-8")
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

    def test_partial_coverage(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(PARTIALLY_DOCUMENTED, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert any(g.name == "undocumented" for g in gaps)
        assert coverage.stats.documented >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(UNDOCUMENTED, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        assert "Docstring coverage:" in coverage.summary()
        context = coverage.to_context()
        assert "process" in context

    def test_docstring_gap_format(self):
        gap = DocstringGap(path="app.py", name="foo", lineno=1, kind="function")
        assert "foo" in gap.format()
        assert "missing docstring" in gap.format()

    def test_include_private(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def _helper():\n    return 1\n",
            encoding="utf-8",
        )
        coverage = DocstringCoverage(str(tmp_path), include_private=True)
        gaps = coverage.analyze()
        assert len(gaps) == 1

    def test_excludes_private_by_default(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def _helper():\n    return 1\n",
            encoding="utf-8",
        )
        coverage = DocstringCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert gaps == []
