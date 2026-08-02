"""Tests for DevAI ImportGraph."""

from pathlib import Path

from devai.import_graph import ImportGraph


SAMPLE_A = """
import os
from .utils import helper

def run():
    return helper()
"""

SAMPLE_B = """
def helper():
    return 1
"""

SAMPLE_CYCLE_A = """
from pkg.b import func_b

def func_a():
    return func_b()
"""

SAMPLE_CYCLE_B = """
from pkg.a import func_a

def func_b():
    return func_a()
"""


class TestImportGraph:
    def test_build_import_edges(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "app.py").write_text(SAMPLE_A, encoding="utf-8")
        (pkg / "utils.py").write_text(SAMPLE_B, encoding="utf-8")

        graph = ImportGraph(str(tmp_path))
        edges = graph.build()
        targets = {e.target for e in edges}
        assert "os" in targets
        assert any(e.source == "pkg.app" for e in edges)

    def test_dependencies_and_dependents(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "app.py").write_text(SAMPLE_A, encoding="utf-8")
        (pkg / "utils.py").write_text(SAMPLE_B, encoding="utf-8")

        graph = ImportGraph(str(tmp_path))
        deps = graph.dependencies("pkg.app")
        assert "os" in deps
        assert "pkg.utils" in deps

    def test_find_cycles(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "a.py").write_text(SAMPLE_CYCLE_A, encoding="utf-8")
        (pkg / "b.py").write_text(SAMPLE_CYCLE_B, encoding="utf-8")

        graph = ImportGraph(str(tmp_path))
        cycles = graph.find_cycles()
        assert len(cycles) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("import json\n", encoding="utf-8")
        graph = ImportGraph(str(tmp_path))
        summary = graph.summary()
        assert "Import graph:" in summary
        context = graph.to_context("app")
        assert "json" in context or "app" in context
