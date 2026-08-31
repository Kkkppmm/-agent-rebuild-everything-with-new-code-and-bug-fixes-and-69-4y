"""Tests for DevAI CodeSymbolIndex."""

from pathlib import Path

from devai.index import CodeSymbolIndex, SymbolInfo


SAMPLE_PROJECT = """
def greet(name):
    return f"Hello, {name}"

class Greeter:
  def say(self, name):
    return greet(name)
"""


class TestCodeSymbolIndex:
    def test_index_python_symbols(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAMPLE_PROJECT, encoding="utf-8")
        index = CodeSymbolIndex(str(tmp_path))
        symbols = index.build()

        names = {s.qualified_name() for s in symbols}
        assert "greet" in names
        assert "Greeter" in names
        assert "Greeter.say" in names

    def test_search_symbols(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAMPLE_PROJECT, encoding="utf-8")
        index = CodeSymbolIndex(str(tmp_path))
        results = index.search("greet")
        assert any(s.name == "greet" for s in results)

    def test_find_exact_symbol(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAMPLE_PROJECT, encoding="utf-8")
        index = CodeSymbolIndex(str(tmp_path))
        matches = index.find("Greeter.say")
        assert len(matches) == 1
        assert matches[0].kind == "method"

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAMPLE_PROJECT, encoding="utf-8")
        index = CodeSymbolIndex(str(tmp_path))
        summary = index.summary()
        assert "Total symbols:" in summary
        context = index.to_context("Greeter")
        assert "Greeter" in context

    def test_symbol_info_qualified_name(self):
        symbol = SymbolInfo(
            name="say",
            kind="method",
            path="app.py",
            lineno=5,
            parent="Greeter",
        )
        assert symbol.qualified_name() == "Greeter.say"

    def test_empty_project(self, tmp_path: Path):
        index = CodeSymbolIndex(str(tmp_path))
        assert index.symbols == []
