"""Tests for ModuleCouplingAnalyzer."""

from pathlib import Path

from devai.module_coupling import ModuleCouplingAnalyzer


SAMPLE_A = """
from pkg.b import func_b

def func_a():
    return func_b()
"""

SAMPLE_B = """
def func_b():
    return 1
"""


class TestModuleCouplingAnalyzer:
    def test_analyze_coupling(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "a.py").write_text(SAMPLE_A, encoding="utf-8")
        (pkg / "b.py").write_text(SAMPLE_B, encoding="utf-8")

        analyzer = ModuleCouplingAnalyzer(str(tmp_path))
        coupling = analyzer.analyze()
        assert len(coupling) >= 2
        stats = analyzer.stats
        assert stats.total_modules >= 2

    def test_instability_ordering(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "a.py").write_text(SAMPLE_A, encoding="utf-8")
        (pkg / "b.py").write_text(SAMPLE_B, encoding="utf-8")

        analyzer = ModuleCouplingAnalyzer(str(tmp_path))
        coupling = analyzer.analyze()
        if len(coupling) >= 2:
            assert coupling[0].instability >= coupling[-1].instability

    def test_health_score(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "b.py").write_text(SAMPLE_B, encoding="utf-8")

        analyzer = ModuleCouplingAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 0.0

    def test_summary_and_context(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "b.py").write_text(SAMPLE_B, encoding="utf-8")

        analyzer = ModuleCouplingAnalyzer(str(tmp_path))
        assert "Module coupling" in analyzer.summary()
        assert "Module coupling" in analyzer.to_context()

    def test_unstable_modules(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "a.py").write_text(SAMPLE_A, encoding="utf-8")
        (pkg / "b.py").write_text(SAMPLE_B, encoding="utf-8")

        analyzer = ModuleCouplingAnalyzer(str(tmp_path), instability_threshold=0.0)
        unstable = analyzer.unstable_modules()
        assert len(unstable) >= 1
