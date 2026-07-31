"""Tests for DebugArtifactDetector."""

from pathlib import Path

from devai.debug_artifacts import DebugArtifact, DebugArtifactDetector

CLEAN_CODE = '''
import logging

logger = logging.getLogger(__name__)

def process(data):
    logger.info("processing %d items", len(data))
    return data
'''

DEBUG_CODE = '''
import pdb
import pprint

def greet(name):
    print(f"hello {name}")
    pprint.pprint({"name": name})

def debug_me():
    breakpoint()
    pdb.set_trace()
'''


class TestDebugArtifactDetector:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(CLEAN_CODE, encoding="utf-8")
        detector = DebugArtifactDetector(str(tmp_path))
        assert detector.analyze() == []
        assert detector.health_score() == 100.0

    def test_detects_debug_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(DEBUG_CODE, encoding="utf-8")
        detector = DebugArtifactDetector(str(tmp_path))
        findings = detector.analyze()
        kinds = {f.kind for f in findings}
        names = {f.name for f in findings}
        assert "print_statement" in kinds
        assert "debugger" in kinds
        assert "print" in names
        assert "breakpoint" in names
        assert "pdb.set_trace" in names
        assert detector.health_score() < 100.0

    def test_skips_test_files_by_default(self, tmp_path: Path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_app.py").write_text('def test_x():\n    print("debug")\n', encoding="utf-8")
        detector = DebugArtifactDetector(str(tmp_path))
        assert detector.analyze() == []

    def test_include_tests(self, tmp_path: Path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_app.py").write_text('def test_x():\n    print("debug")\n', encoding="utf-8")
        detector = DebugArtifactDetector(str(tmp_path), include_tests=True)
        assert len(detector.analyze()) == 1

    def test_by_kind(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(DEBUG_CODE, encoding="utf-8")
        detector = DebugArtifactDetector(str(tmp_path))
        debugger = detector.by_kind("debugger")
        assert any(f.name == "breakpoint" for f in debugger)

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(DEBUG_CODE, encoding="utf-8")
        detector = DebugArtifactDetector(str(tmp_path))
        high = detector.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(DEBUG_CODE, encoding="utf-8")
        detector = DebugArtifactDetector(str(tmp_path))
        assert "Debug artifacts:" in detector.summary()
        assert "breakpoint" in detector.to_context()

    def test_format(self):
        finding = DebugArtifact(
            path="app.py",
            function="greet",
            name="print",
            lineno=5,
            kind="print_statement",
            severity="medium",
            message="use logging",
        )
        assert "app.py:5" in finding.format()
        assert "greet()" in finding.format()
