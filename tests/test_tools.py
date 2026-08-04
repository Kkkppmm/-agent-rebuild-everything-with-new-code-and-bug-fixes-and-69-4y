"""Tests for DevAI tools."""

import pytest

from devai.core.exceptions import ToolError
from devai.tools import (
    ToolRegistry,
    count_complexity,
    explain_code,
    lint_python,
    list_files,
    read_file,
    search_code,
)


class TestCodeUtils:
    def test_explain_code_python(self):
        code = "def hello():\n    return 42\n\nclass Foo:\n    pass"
        result = explain_code(code)
        assert "hello" in result
        assert "Foo" in result

    def test_explain_code_syntax_error(self):
        result = explain_code("def broken(")
        assert "Syntax error" in result

    def test_lint_python_clean(self):
        code = 'def foo():\n    """Doc."""\n    return 1'
        result = lint_python(code)
        assert "No issues" in result

    def test_lint_python_issues(self):
        code = "def foo():\n    print('hi')\n    try:\n        pass\n    except:\n        pass"
        result = lint_python(code)
        assert "print" in result or "except" in result

    def test_count_complexity(self):
        code = (
            "def simple():\n    return 1\n\n"
            "def complex(x):\n    if x > 0:\n"
            "        for i in range(x):\n            if i % 2:\n                pass"
        )
        result = count_complexity(code)
        assert "simple" in result
        assert "complex" in result

    def test_read_file(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("print('hello')")
        result = read_file(str(f))
        assert "hello" in result

    def test_read_file_not_found(self):
        result = read_file("/nonexistent/file.py")
        assert "not found" in result.lower()

    def test_list_files(self, tmp_path):
        (tmp_path / "a.py").write_text("")
        (tmp_path / "b.py").write_text("")
        result = list_files(str(tmp_path), "*.py")
        assert "a.py" in result
        assert "b.py" in result

    def test_search_code(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("TODO: fix this\nx = 1")
        result = search_code("TODO", str(tmp_path))
        assert "TODO" in result


class TestToolRegistry:
    def test_register_and_execute(self):
        registry = ToolRegistry()

        def greet(name: str) -> str:
            return f"Hello, {name}!"

        registry.register(greet)
        assert "greet" in registry
        assert len(registry) == 1
        result = registry.execute("greet", {"name": "Dev"})
        assert result == "Hello, Dev!"

    def test_unknown_tool(self):
        registry = ToolRegistry()
        with pytest.raises(ToolError, match="Unknown tool"):
            registry.execute("missing", {})

    def test_get_tools_schema(self):
        registry = ToolRegistry()
        registry.register(read_file)
        tools = registry.get_tools()
        assert len(tools) == 1
        assert tools[0].name == "read_file"
