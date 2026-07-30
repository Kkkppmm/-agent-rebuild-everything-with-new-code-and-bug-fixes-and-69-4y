"""Tests for DevAI code indexer."""

from pathlib import Path

from devai.indexer import CodeIndexer, CodeSymbol


SAMPLE = '''
def greet(name):
    return f"hi {name}"

class Greeter:
    def say(self, msg):
        return msg
'''


class TestCodeIndexer:
    def test_index_file(self, tmp_path: Path):
        path = tmp_path / "sample.py"
        path.write_text(SAMPLE)
        indexer = CodeIndexer(str(tmp_path))
        symbols = indexer.index_file(path, relative=True)
        assert len(symbols) == 3
        kinds = {s.kind for s in symbols}
        assert kinds == {"function", "class", "method"}

    def test_search(self, tmp_path: Path):
        path = tmp_path / "sample.py"
        path.write_text(SAMPLE)
        indexer = CodeIndexer(str(tmp_path))
        indexer.index_file(path)
        matches = indexer.search("greet")
        assert len(matches) == 2

    def test_to_context(self, tmp_path: Path):
        path = tmp_path / "sample.py"
        path.write_text(SAMPLE)
        indexer = CodeIndexer(str(tmp_path))
        indexer.index_file(path)
        context = indexer.to_context()
        assert "greet" in context
        assert "Greeter" in context

    def test_by_path(self, tmp_path: Path):
        path = tmp_path / "sample.py"
        path.write_text(SAMPLE)
        indexer = CodeIndexer(str(tmp_path))
        indexer.index_file(path)
        rel = str(path.relative_to(tmp_path))
        assert len(indexer.by_path(rel)) == 3

    def test_symbol_display(self):
        symbol = CodeSymbol(
            name="foo",
            kind="method",
            path="mod.py",
            line=10,
            parent="Bar",
            signature="(x)",
        )
        assert "Bar.foo" in symbol.display() and "(x)" in symbol.display()
