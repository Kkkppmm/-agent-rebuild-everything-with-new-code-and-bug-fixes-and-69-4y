"""Tests for DuplicateCodeDetector."""

from pathlib import Path

from devai.duplicate_code import DuplicateCodeDetector

DUPLICATE_BLOCK = """
def process_items(items):
    result = []
    for item in items:
        if item is not None:
            if item > 0:
                result.append(item * 2)
    return result
"""

UNIQUE = """
def unique_function(x):
    return x + 1
"""


class TestDuplicateCodeDetector:
    def test_no_duplicates(self, tmp_path: Path):
        (tmp_path / "a.py").write_text(UNIQUE, encoding="utf-8")
        detector = DuplicateCodeDetector(str(tmp_path), min_lines=3)
        clusters = detector.analyze()
        assert clusters == []
        assert detector.health_score() == 100.0

    def test_detects_duplicates(self, tmp_path: Path):
        (tmp_path / "a.py").write_text(DUPLICATE_BLOCK, encoding="utf-8")
        (tmp_path / "b.py").write_text(DUPLICATE_BLOCK, encoding="utf-8")
        detector = DuplicateCodeDetector(str(tmp_path), min_lines=5)
        clusters = detector.analyze()
        assert len(clusters) >= 1
        assert clusters[0].occurrences >= 2
        assert detector.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "a.py").write_text(DUPLICATE_BLOCK, encoding="utf-8")
        (tmp_path / "b.py").write_text(DUPLICATE_BLOCK, encoding="utf-8")
        detector = DuplicateCodeDetector(str(tmp_path), min_lines=5)
        summary = detector.summary()
        assert "Duplicate code" in summary
        context = detector.to_context()
        assert "Clusters:" in context

    def test_stats(self, tmp_path: Path):
        (tmp_path / "a.py").write_text(DUPLICATE_BLOCK, encoding="utf-8")
        (tmp_path / "b.py").write_text(DUPLICATE_BLOCK, encoding="utf-8")
        detector = DuplicateCodeDetector(str(tmp_path), min_lines=5)
        detector.analyze()
        stats = detector.stats
        assert stats.total_clusters >= 1
        assert stats.files_affected >= 2
