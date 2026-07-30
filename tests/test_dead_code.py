"""Tests for DeadCodeAnalyzer."""

from pathlib import Path

from devai.dead_code import DeadCodeAnalyzer

USED = '''
def helper():
    return 42

def main():
    return helper()
'''

DEAD = '''
def unused_function():
    return "never called"

class UnusedClass:
    pass

def used_function():
    return used_function.__name__
'''


class TestDeadCodeAnalyzer:
    def test_no_dead_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(USED, encoding="utf-8")
        analyzer = DeadCodeAnalyzer(str(tmp_path))
        dead = analyzer.analyze()
        assert dead == []
        assert analyzer.health_score() == 100.0

    def test_detects_dead_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(DEAD, encoding="utf-8")
        analyzer = DeadCodeAnalyzer(str(tmp_path))
        dead = analyzer.analyze()
        names = {s.name for s in dead}
        assert "unused_function" in names
        assert "UnusedClass" in names
        assert "used_function" not in names
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(DEAD, encoding="utf-8")
        analyzer = DeadCodeAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Dead code" in summary
        context = analyzer.to_context()
        assert "unused_function" in context

    def test_stats(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(DEAD, encoding="utf-8")
        analyzer = DeadCodeAnalyzer(str(tmp_path))
        analyzer.analyze()
        stats = analyzer.stats
        assert stats.dead_symbols >= 2
        assert stats.total_symbols >= 3
