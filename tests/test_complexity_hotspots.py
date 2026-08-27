"""Tests for ComplexityHotspotAnalyzer."""

from pathlib import Path

from devai.complexity_hotspots import ComplexityHotspotAnalyzer

SIMPLE = '''
def add(a, b):
    return a + b
'''

COMPLEX = '''
def complex_fn(x):
    if x > 0:
        if x > 10:
            if x > 20:
                if x > 30:
                    if x > 40:
                        return x * 2
    for i in range(x):
        if i % 2 == 0:
            if i % 3 == 0:
                pass
    return x
'''


class TestComplexityHotspotAnalyzer:
    def test_ranks_complex_files_higher(self, tmp_path: Path):
        (tmp_path / "simple.py").write_text(SIMPLE, encoding="utf-8")
        (tmp_path / "complex.py").write_text(COMPLEX, encoding="utf-8")
        analyzer = ComplexityHotspotAnalyzer(str(tmp_path), complexity_threshold=5)
        hotspots = analyzer.analyze()
        assert len(hotspots) >= 1
        assert hotspots[0].path == "complex.py"
        assert hotspots[0].score > 0

    def test_health_score(self, tmp_path: Path):
        (tmp_path / "simple.py").write_text(SIMPLE, encoding="utf-8")
        analyzer = ComplexityHotspotAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "complex.py").write_text(COMPLEX, encoding="utf-8")
        analyzer = ComplexityHotspotAnalyzer(str(tmp_path), complexity_threshold=5)
        summary = analyzer.summary()
        assert "Hotspots" in summary
        context = analyzer.to_context()
        assert "hotspot" in context.lower()

    def test_stats(self, tmp_path: Path):
        (tmp_path / "complex.py").write_text(COMPLEX, encoding="utf-8")
        analyzer = ComplexityHotspotAnalyzer(str(tmp_path), complexity_threshold=5)
        analyzer.analyze()
        stats = analyzer.stats
        assert stats.files_analyzed >= 1
        assert stats.worst_score > 0
