"""Tests for FilePermissionAnalyzer."""

from pathlib import Path

from devai.file_permissions import FilePermissionAnalyzer

SAFE_CODE = '''
import os

def setup(path):
    os.chmod(path, 0o644)
'''

RISKY_CODE = '''
import os

def setup(path):
    os.chmod(path, 0o777)
    os.makedirs("/tmp/data", mode=0o777)
'''


class TestFilePermissionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = FilePermissionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_world_writable(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = FilePermissionAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = FilePermissionAnalyzer(str(tmp_path))
        assert "File permissions:" in analyzer.summary()
        assert "File permission analysis:" in analyzer.to_context()
