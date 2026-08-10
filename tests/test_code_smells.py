"""Tests for CodeSmellDetector."""

from pathlib import Path

from devai.code_smells import CodeSmell, CodeSmellDetector


CLEAN = '''
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
'''

SMELLY = '''
def process(data, a, b, c, d, e, f):
    result = []
    for item in data:
        if item > 0:
            if item % 2 == 0:
                if item > 10:
                    if item < 100:
                        result.append(item)
    try:
        pass
    except:
        pass
    return result
'''

GOD_CLASS = "\n".join(
    [f"    def method_{i}(self): pass" for i in range(25)]
    + ["class BigService:"]
)
GOD_CLASS = "class BigService:\n" + "\n".join(
    f"    def method_{i}(self): pass" for i in range(25)
)


class TestCodeSmellDetector:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(CLEAN, encoding="utf-8")
        detector = CodeSmellDetector(str(tmp_path))
        smells = detector.analyze()
        assert smells == []
        assert detector.health_score() == 100.0

    def test_detects_smells(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SMELLY, encoding="utf-8")
        detector = CodeSmellDetector(str(tmp_path), max_params=5, max_nesting=3)
        smells = detector.analyze()
        kinds = {s.kind for s in smells}
        assert "too_many_params" in kinds
        assert "deep_nesting" in kinds
        assert "bare_except" in kinds
        assert detector.health_score() < 100.0

    def test_god_class(self, tmp_path: Path):
        (tmp_path / "svc.py").write_text(GOD_CLASS, encoding="utf-8")
        detector = CodeSmellDetector(str(tmp_path), max_methods=20)
        smells = detector.analyze()
        assert any(s.kind == "god_class" for s in smells)

    def test_by_kind_and_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SMELLY, encoding="utf-8")
        detector = CodeSmellDetector(str(tmp_path), max_params=3)
        detector.analyze()
        assert len(detector.by_kind("too_many_params")) >= 1
        assert len(detector.by_severity("high")) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SMELLY, encoding="utf-8")
        detector = CodeSmellDetector(str(tmp_path))
        assert "Code smells" in detector.summary()
        assert "Code smell analysis" in detector.to_context()

    def test_format(self):
        smell = CodeSmell(
            path="app.py",
            name="process",
            lineno=2,
            kind="long_function",
            message="60 lines",
            severity="medium",
        )
        assert "app.py:2" in smell.format()
        assert "long_function" in smell.format()
