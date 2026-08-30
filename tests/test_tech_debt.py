"""Tests for TechDebtScanner."""

from pathlib import Path

from devai.tech_debt import TechDebtItem, TechDebtScanner


PYTHON_WITH_DEBT = '''
def foo():
    # TODO: implement this
    pass

def bar():
    # FIXME: broken edge case
    return 1
'''

JS_WITH_DEBT = """
function run() {
    // HACK: temporary workaround
    return true;
}
"""


class TestTechDebtScanner:
    def test_no_debt(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        scanner = TechDebtScanner(str(tmp_path))
        assert scanner.scan() == []
        assert scanner.health_score() == 100.0

    def test_detects_python_markers(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(PYTHON_WITH_DEBT, encoding="utf-8")
        scanner = TechDebtScanner(str(tmp_path))
        items = scanner.scan()
        markers = {i.marker for i in items}
        assert "TODO" in markers
        assert "FIXME" in markers
        assert scanner.stats.files_with_debt == 1

    def test_detects_js_markers(self, tmp_path: Path):
        (tmp_path / "app.js").write_text(JS_WITH_DEBT, encoding="utf-8")
        scanner = TechDebtScanner(str(tmp_path))
        items = scanner.scan()
        assert any(i.marker == "HACK" for i in items)

    def test_by_marker(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(PYTHON_WITH_DEBT, encoding="utf-8")
        scanner = TechDebtScanner(str(tmp_path))
        todos = scanner.by_marker("TODO")
        assert len(todos) == 1
        assert todos[0].message == "implement this"

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(PYTHON_WITH_DEBT, encoding="utf-8")
        scanner = TechDebtScanner(str(tmp_path))
        assert "Tech debt" in scanner.summary()
        assert "Tech debt scan" in scanner.to_context()

    def test_format(self):
        item = TechDebtItem(path="app.py", lineno=3, marker="TODO", message="fix later")
        assert "app.py:3" in item.format()
        assert "TODO" in item.format()
