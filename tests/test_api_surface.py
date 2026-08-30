"""Tests for APISurfaceAnalyzer."""

from pathlib import Path

from devai.api_surface import APISurfaceAnalyzer

DOCUMENTED = '''
"""Module docstring."""

__all__ = ["greet"]

def greet(name: str) -> str:
    """Say hello."""
    return f"hello {name}"

def _private():
    pass

class PublicClass:
    """A public class."""

    def method(self):
        pass
'''

UNDOCUMENTED = '''
def exposed():
    return 1

class Undocumented:
    pass
'''


class TestAPISurfaceAnalyzer:
    def test_finds_public_symbols(self, tmp_path: Path):
        src = tmp_path / "src" / "mypkg"
        src.mkdir(parents=True)
        (src / "mod.py").write_text(DOCUMENTED, encoding="utf-8")
        analyzer = APISurfaceAnalyzer(str(tmp_path), source_dir="src")
        symbols = analyzer.symbols
        names = {s.name for s in symbols}
        assert "greet" in names
        assert "PublicClass" in names
        assert "_private" not in names

    def test_detects_undocumented(self, tmp_path: Path):
        src = tmp_path / "src" / "mypkg"
        src.mkdir(parents=True)
        (src / "mod.py").write_text(UNDOCUMENTED, encoding="utf-8")
        analyzer = APISurfaceAnalyzer(str(tmp_path), source_dir="src")
        gaps = analyzer.undocumented()
        assert len(gaps) >= 2
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        src = tmp_path / "src" / "mypkg"
        src.mkdir(parents=True)
        (src / "mod.py").write_text(DOCUMENTED, encoding="utf-8")
        analyzer = APISurfaceAnalyzer(str(tmp_path), source_dir="src")
        summary = analyzer.summary()
        assert "Public symbols" in summary
        context = analyzer.to_context()
        assert "API surface" in context

    def test_stats(self, tmp_path: Path):
        src = tmp_path / "src" / "mypkg"
        src.mkdir(parents=True)
        (src / "mod.py").write_text(DOCUMENTED, encoding="utf-8")
        analyzer = APISurfaceAnalyzer(str(tmp_path), source_dir="src")
        stats = analyzer.stats
        assert stats.public_symbols >= 2
        assert stats.modules_with_all >= 1
