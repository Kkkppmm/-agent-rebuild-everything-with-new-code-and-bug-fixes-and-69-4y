"""Tests for PathTraversalAnalyzer."""

from pathlib import Path

from devai.path_traversal import PathTraversalAnalyzer

SAFE_CODE = '''
from pathlib import Path

BASE = Path("/var/data")

def read_config(name: str):
    path = BASE / "configs" / name
    if not path.resolve().is_relative_to(BASE.resolve()):
        raise ValueError("invalid path")
    return path.read_text()
'''

RISKY_CODE = '''
import os
from pathlib import Path

def download_file(filename, upload_dir):
    path = os.path.join(upload_dir, filename)
    return open(path).read()

def read_user_file(user_path):
  return Path(user_path).read_text()

def serve(request):
    f = request.args.get("file")
    return open(f"/data/{f}").read()
'''


class TestPathTraversalAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = PathTraversalAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = PathTraversalAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "join_user_input" in patterns or "dynamic_open" in patterns
        assert analyzer.health_score() < 100.0

    def test_by_pattern(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = PathTraversalAnalyzer(str(tmp_path))
        joined = analyzer.by_pattern("join_user_input")
        assert len(joined) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = PathTraversalAnalyzer(str(tmp_path))
        assert "Path traversal" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
