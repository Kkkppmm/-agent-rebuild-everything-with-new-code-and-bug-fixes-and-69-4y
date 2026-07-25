"""Tests for tool registry and code utilities."""


from devai.tools.base import Tool
from devai.tools.code import explain_code, extract_functions, format_json, lint_python
from devai.tools.registry import ToolRegistry

SAMPLE_CODE = '''\
def add(a, b):
    """Add two numbers."""
    return a + b

class Calculator:
    pass
'''


def test_explain_code_python():
    result = explain_code(SAMPLE_CODE)
    assert "add" in result
    assert "Calculator" in result


def test_extract_functions():
    functions = extract_functions(SAMPLE_CODE)
    assert len(functions) == 1
    assert functions[0]["name"] == "add"
    assert functions[0]["docstring"] == "Add two numbers."


def test_lint_python_bare_except():
    code = "try:\n    x = 1\nexcept:\n    pass\n"
    issues = lint_python(code)
    assert any("Bare except" in issue["message"] for issue in issues)


def test_tool_from_function():
    def multiply(x: int, y: int) -> int:
        """Multiply two integers."""
        return x * y

    tool = Tool(multiply)
    assert tool.definition.name == "multiply"
    assert "x" in tool.definition.parameters["properties"]
    assert tool.run(x=3, y=4) == 12


def test_tool_registry_decorator():
    registry = ToolRegistry()

    @registry.register(description="Greet someone")
    def greet(name: str) -> str:
        return f"Hello, {name}!"

    assert "greet" in registry
    assert registry.run("greet", {"name": "Dev"}) == "Hello, Dev!"
    assert len(registry.definitions()) == 1


def test_format_json():
    assert format_json('{"a": 1}') == '{\n  "a": 1\n}'
