"""Tests for tools module."""

import pytest

from devai.core.exceptions import ToolExecutionError
from devai.tools import (
    ToolRegistry,
    count_complexity,
    create_default_registry,
    explain_code,
    lint_python,
    read_file,
    search_code,
)


SAMPLE_CODE = '''\
def hello():
    """Say hello."""
    return "hello"

def bad():
    try:
        pass
    except:
        pass
'''


class TestCodeTools:
    def test_explain_code_python(self):
        result = explain_code(SAMPLE_CODE)
        assert "hello" in result
        assert "Functions" in result

    def test_explain_code_syntax_error(self):
        result = explain_code("def (", language="python")
        assert "Syntax error" in result

    def test_lint_python_clean(self):
        result = lint_python("value = 1\n")
        assert "No issues" in result

    def test_lint_python_bare_except(self):
        result = lint_python("try:\n  pass\nexcept:\n  pass\n")
        assert "Bare except" in result

    def test_search_code(self):
        result = search_code(SAMPLE_CODE, "hello")
        assert "Line" in result

    def test_search_code_no_match(self):
        result = search_code("x = 1", "zzz")
        assert "No matches" in result

    def test_count_complexity(self):
        result = count_complexity(SAMPLE_CODE)
        assert "hello" in result

    def test_read_file(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("print('hi')")
        result = read_file(str(f))
        assert "print" in result


class TestToolRegistry:
    def test_register_and_execute(self):
        reg = ToolRegistry()
        reg.register("add", lambda a, b: a + b, "Add numbers", {
            "type": "object",
            "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
        })
        assert reg.execute("add", {"a": 2, "b": 3}) == "5"

    def test_execute_unknown(self):
        reg = ToolRegistry()
        with pytest.raises(ToolExecutionError):
            reg.execute("missing", {})

    def test_list_tools(self):
        reg = create_default_registry()
        tools = reg.list_tools()
        assert len(tools) >= 6
        names = {t.name for t in tools}
        assert "explain_code" in names
        assert "lint_python" in names
