"""Tests for DebugArtifactDetector."""

from pathlib import Path

from devai.debug_artifacts import DebugArtifactDetector


SAFE_CODE = '''
import logging

def run():
    logging.info("started")
'''

DEBUG_CODE = '''
import pdb

def debug_me():
    print("debugging")
    breakpoint()
    pdb.set_trace()
'''


class TestDebugArtifactDetector:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        detector = DebugArtifactDetector(str(tmp_path))
        assert detector.analyze() == []
        assert detector.health_score() == 100.0

    def test_detects_debug_artifacts(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(DEBUG_CODE, encoding="utf-8")
        detector = DebugArtifactDetector(str(tmp_path))
        findings = detector.analyze()
        kinds = {f.kind for f in findings}
        assert "print" in kinds
        assert "breakpoint" in kinds
        assert "pdb" in kinds
        assert "pdb_import" in kinds

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(DEBUG_CODE, encoding="utf-8")
        detector = DebugArtifactDetector(str(tmp_path))
        assert "Debug artifacts" in detector.summary()
        assert "Findings:" in detector.to_context()
