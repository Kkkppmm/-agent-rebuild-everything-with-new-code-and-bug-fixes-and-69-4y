"""Tests for ToolRegistry and code tools."""

import tempfile
from pathlib import Path

from devai.tools.code_tools import explain_code, lint_python, search_code
from devai.tools.registry import ToolRegistry


def test_register_decorator():
    registry = ToolRegistry()

    @registry.register
    def greet(name: str) -> str:
        """Say hello."""
        return f"Hello {name}"

    assert "greet" in registry
    assert len(registry) == 1
    defs = registry.get_definitions()
    assert defs[0].name == "greet"
    assert defs[0].description == "Say hello."


def test_execute_tool():
    registry = ToolRegistry()

    @registry.register
    def add(a: int, b: int) -> int:
        return a + b

    result = registry.execute("add", {"a": 2, "b": 3})
    assert result == "5"


def test_explain_python_code():
    code = "def hello():\n    return 'hi'\n\nclass Foo:\n    pass"
    result = explain_code(code, language="python")
    assert "hello" in result
    assert "Foo" in result


def test_explain_non_python():
    result = explain_code("console.log('hi')", language="javascript")
    assert "javascript" in result


def test_lint_python_clean():
    code = 'def add(a, b):\n    """Add two numbers."""\n    return a + b\n'
    result = lint_python(code)
    assert "No issues found" in result


def test_lint_python_syntax_error():
    result = lint_python("def broken(:\n    pass")
    assert "SYNTAX ERROR" in result


def test_search_code():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "sample.py"
        path.write_text("def target_function():\n    pass\n\ndef other():\n    pass\n")
        result = search_code(tmpdir, r"target_function")
        assert "target_function" in result
        assert "sample.py" in result
