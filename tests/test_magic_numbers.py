"""Tests for MagicNumberDetector."""

from pathlib import Path

from devai.magic_numbers import MagicNumber, MagicNumberDetector


GOOD_CODE = '''
MAX_RETRIES = 3
TIMEOUT_SECONDS = 30

def process(items):
    if len(items) == 0:
        return None
    return items[0]
'''

BAD_CODE = '''
def calculate_discount(price):
    if price > 100:
        return price * 0.85
    return price

def wait():
    return range(5000)
'''


class TestMagicNumberDetector:
    def test_allows_module_constants(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(GOOD_CODE, encoding="utf-8")
        detector = MagicNumberDetector(str(tmp_path))
        findings = detector.analyze()
        assert all(f.value not in ("3", "30") for f in findings)

    def test_detects_magic_numbers(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BAD_CODE, encoding="utf-8")
        detector = MagicNumberDetector(str(tmp_path))
        findings = detector.analyze()
        values = {f.value for f in findings}
        assert "100" in values
        assert "0.85" in values
        assert detector.health_score() < 100.0

    def test_by_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BAD_CODE, encoding="utf-8")
        detector = MagicNumberDetector(str(tmp_path))
        comparisons = detector.by_context("comparison")
        assert any(f.value == "100" for f in comparisons)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BAD_CODE, encoding="utf-8")
        detector = MagicNumberDetector(str(tmp_path))
        assert "Magic numbers:" in detector.summary()
        assert "Magic number analysis" in detector.to_context()

    def test_format(self):
        finding = MagicNumber(
            path="app.py",
            value="100",
            lineno=3,
            col_offset=15,
            context="comparison",
            message="consider extracting to a named constant",
        )
        assert "app.py:3:15" in finding.format()
        assert "comparison" in finding.format()

    def test_allows_trivial_values(self, tmp_path: Path):
        code = """
def foo(x):
    if x == 0:
        return x + 1
    return x - 1
"""
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
        detector = MagicNumberDetector(str(tmp_path))
        assert detector.analyze() == []

    def test_no_findings_health_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def foo(): return 1\n", encoding="utf-8")
        detector = MagicNumberDetector(str(tmp_path))
        assert detector.health_score() == 100.0
