"""Tests for code tools."""

from devai.tools.code_tools import (
    explain_code,
    lint_python,
    search_code,
    read_file,
    count_complexity,
)
import tempfile
import os


def test_explain_code_python():
    code = "class Foo:\n    def bar(self):\n        pass"
    result = explain_code(code, "python")
    assert "Foo" in result
    assert "bar" in result


def test_explain_code_syntax_error():
    result = explain_code("def broken(", "python")
    assert "Syntax error" in result


def test_lint_python_clean():
    code = "def f():\n    return 1"
    result = lint_python(code)
    assert result["count"] == 0


def test_lint_python_bare_except():
    code = "try:\n    pass\nexcept:\n    pass"
    result = lint_python(code)
    assert result["count"] >= 1


def test_search_code():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.py")
        with open(path, "w") as f:
            f.write("def hello_world():\n    pass\n")
        results = search_code(tmp, "hello_world")
        assert len(results) >= 1
        assert "hello_world" in results[0]["content"]


def test_read_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("line1\nline2\n")
        path = f.name
    result = read_file(path)
    assert "line1" in result
    os.unlink(path)


def test_count_complexity():
    code = """
def simple():
    return 1

def complex(x):
    if x > 0:
        for i in range(x):
            if i % 2 == 0:
                pass
    return x
"""
    result = count_complexity(code)
    assert result["max_complexity"] >= 3
    assert "simple" in result["functions"]
    assert "complex" in result["functions"]
