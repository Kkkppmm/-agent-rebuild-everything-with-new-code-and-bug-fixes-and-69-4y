"""Tests for DevAI TypingCoverage."""

from pathlib import Path

from devai.typing_coverage import TypingCoverage, TypingGap


FULLY_TYPED = """
def add(a: int, b: int) -> int:
    return a + b
"""

PARTIALLY_TYPED = """
def greet(name: str):
    return f"hi {name}"
"""

UNTYPED = """
def process(data):
    return data
"""

CLASS_SAMPLE = """
class Service:
    def run(self, x: int) -> int:
        return x

    def helper(self, y):
        return y
"""


class TestTypingCoverage:
    def test_fully_typed(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FULLY_TYPED, encoding="utf-8")
        coverage = TypingCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert gaps == []
        assert coverage.coverage_pct() == 100.0

    def test_detects_missing_hints(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(UNTYPED, encoding="utf-8")
        coverage = TypingCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert len(gaps) == 1
        assert "data" in gaps[0].missing

    def test_partial_return_missing(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(PARTIALLY_TYPED, encoding="utf-8")
        coverage = TypingCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert any("return" in g.missing for g in gaps)

    def test_class_methods(self, tmp_path: Path):
        (tmp_path / "svc.py").write_text(CLASS_SAMPLE, encoding="utf-8")
        coverage = TypingCoverage(str(tmp_path))
        gaps = coverage.analyze()
        assert any(g.name == "Service.helper" for g in gaps)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(UNTYPED, encoding="utf-8")
        coverage = TypingCoverage(str(tmp_path))
        assert "Typing coverage:" in coverage.summary()
        context = coverage.to_context()
        assert "process" in context

    def test_typing_gap_format(self):
        gap = TypingGap(path="app.py", name="foo", lineno=1, missing=["x", "return"])
        assert "foo" in gap.format()
        assert "x" in gap.format()
