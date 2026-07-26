"""Tests for code utility tools."""

import pytest

from devai.tools.code_utils import (
    count_complexity,
    explain_code,
    lint_python,
    read_file,
    search_code,
)
from devai.tools.registry import ToolRegistry, default_registry


SAMPLE_CODE = '''import os

def hello(name):
    if name:
        return f"Hello {name}"
    return "Hello world"

class Greeter:
    def greet(self):
        pass
'''


def test_explain_code():
    result = explain_code(SAMPLE_CODE)
    assert "hello" in result
    assert "Greeter" in result


def test_explain_code_syntax_error():
    result = explain_code("def broken(")
    assert "Syntax error" in result


def test_lint_python_clean():
    issues = lint_python("x = 1\n")
    assert isinstance(issues, list)


def test_lint_python_trailing_whitespace():
    issues = lint_python("x = 1   \n")
    assert any("trailing" in i for i in issues)


def test_lint_python_bare_except():
    issues = lint_python("try:\n    pass\nexcept:\n    pass\n")
    assert any("bare except" in i for i in issues)


def test_count_complexity():
    result = count_complexity(SAMPLE_CODE)
    assert "hello" in result
    assert result["hello"] >= 2


def test_search_code(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("def findme():\n    pass\n")
    results = search_code(str(tmp_path), "findme")
    assert len(results) == 1


def test_read_file(tmp_path):
    f = tmp_path / "hello.txt"
    f.write_text("hello world")
    assert read_file(str(f)) == "hello world"


def test_default_registry():
    registry = default_registry()
    assert len(registry) == 6
    assert "explain_code" in registry


def test_registry_execute():
    registry = default_registry()
    result = registry.execute("explain_code", {"code": "x = 1"})
    assert "Lines" in result


def test_registry_unknown_tool():
    registry = ToolRegistry()
    from devai.core.exceptions import ToolError

    with pytest.raises(ToolError, match="Unknown tool"):
        registry.execute("nope", {})
