"""Tests for DevAI CodeMetrics."""

from pathlib import Path

from devai.code_metrics import CodeMetrics


SIMPLE = """
def add(a, b):
    return a + b

class Service:
    def run(self):
        return 1
"""

COMPLEX = """
def complex_fn(x):
    if x > 0:
        if x > 10:
            for i in range(x):
                if i % 2 == 0:
                    pass
    elif x < 0:
        while x < 0:
            x += 1
    return x
"""


class TestCodeMetrics:
    def test_basic_metrics(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SIMPLE, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        stats = metrics.analyze()
        assert stats.files == 1
        assert stats.functions == 2
        assert stats.classes == 1
        assert stats.lines_code > 0

    def test_high_complexity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(COMPLEX, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path), complexity_threshold=5)
        high = metrics.high_complexity()
        assert len(high) == 1
        assert high[0].name == "complex_fn"
        assert high[0].complexity >= 5

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SIMPLE, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        summary = metrics.summary()
        assert "Python files: 1" in summary
        context = metrics.to_context()
        assert "Static code metrics" in context

    def test_largest_files(self, tmp_path: Path):
        (tmp_path / "small.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "large.py").write_text(SIMPLE + "\n" * 20, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        largest = metrics.largest_files(1)
        assert largest[0].path == "large.py"

    def test_skips_hidden_dirs(self, tmp_path: Path):
        hidden = tmp_path / ".git" / "ignored.py"
        hidden.parent.mkdir(parents=True)
        hidden.write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "visible.py").write_text("y = 2\n", encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        stats = metrics.analyze()
        assert stats.files == 1
