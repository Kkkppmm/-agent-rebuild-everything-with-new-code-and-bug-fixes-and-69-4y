"""Tests for DevAI tools."""

from devai.tools.code import count_complexity, explain_code, lint_python, read_file
from devai.tools.registry import ToolRegistry


def test_explain_code_python():
    code = "def hello():\n    return 'world'"
    result = explain_code(code, "python")
    assert "hello" in result


def test_lint_python_clean():
    code = "def foo():\n    return 1"
    result = lint_python(code)
    assert "No issues" in result


def test_lint_python_syntax_error():
    result = lint_python("def foo(:")
    assert "Syntax error" in result


def test_count_complexity():
    code = "def simple():\n    return 1\n\ndef complex(x):\n    if x > 0:\n        for i in range(x):\n            if i % 2:\n                pass"
    result = count_complexity(code)
    assert "simple" in result
    assert "complex" in result


def test_tool_registry():
    registry = ToolRegistry()

    def greet(name: str) -> str:
        return f"Hello {name}"

    registry.register("greet", greet, "Greet someone", {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    })
    assert "greet" in registry
    assert registry.execute("greet", {"name": "World"}) == "Hello World"


def test_read_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("line1\nline2")
    result = read_file(str(f))
    assert "line1" in result
