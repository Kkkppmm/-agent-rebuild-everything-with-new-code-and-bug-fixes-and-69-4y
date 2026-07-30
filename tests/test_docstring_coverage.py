"""Tests for DevAI DocstringCoverage."""

from pathlib import Path

from devai.docstring_coverage import DocstringCoverage, DocstringGap


FULLY_DOCUMENTED = '''"""Module docstring."""

def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
'''

PARTIAL = '''"""Module docstring."""

def greet(name: str):
    return f"hi {name}"
'''

UNDOCUMENTED = """
def process(data):
    return data
"""

CLASS_SAMPLE = '''"""Module docstring."""

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
        (tmp_path / "app.py").write_text(FULLY_DOCUMENTED, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert gaps == []
        assert coverage.coverage_pct() == 100.0

    def test_detects_missing_docstrings(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(UNDOCUMENTED, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert any(g.name == "process" for g in gaps)
        assert any(g.kind == "module" for g in gaps)

    def test_partial_coverage(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(PARTIAL, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert any(g.name == "greet" for g in gaps)
        assert coverage.coverage_pct() < 100.0

    def test_class_methods(self, tmp_path: Path):
        (tmp_path / "svc.py").write_text(CLASS_SAMPLE, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert any(g.name == "Service.helper" for g in gaps)
        assert not any(g.name == "Service.run" for g in gaps)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(UNDOCUMENTED, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        assert "Docstring coverage:" in coverage.summary()
        context = coverage.to_context()
        assert "process" in context

    def test_docstring_gap_format(self):
        gap = DocstringGap(path="app.py", name="foo", kind="function", lineno=1)
        assert "foo" in gap.format()
        assert "function" in gap.format()

    def test_skips_private_methods(self, tmp_path: Path):
        code = '''"""Module."""

class Foo:
  """Foo class."""

  def _private(self):
      pass
'''
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert not any("_private" in g.name for g in gaps)

    def test_include_private(self, tmp_path: Path):
        code = '''"""Module."""

class Foo:
  """Foo class."""

  def _private(self):
      pass
'''
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path), include_private=True)
        gaps = coverage.analyze()
        assert any("_private" in g.name for g in gaps)

    def test_module_stats(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FULLY_DOCUMENTED, encoding="utf-8")
        coverage = DocstringCoverage(str(tmp_path))
        coverage.analyze()
        assert coverage.stats.module_coverage_pct == 100.0
