"""Tests for code tools."""

from devai.tools.code import (
    count_complexity,
    explain_code,
    lint_python,
    read_file,
    search_code,
)


def test_explain_code():
    code = "def hello():\n    return 'world'\n"
    result = explain_code(code)
    assert "hello" in result
    assert "Functions" in result


def test_explain_code_syntax_error():
    result = explain_code("def broken(")
    assert "Syntax error" in result


def test_lint_python_valid():
    result = lint_python("x = 1\n")
    assert "No syntax errors" in result


def test_lint_python_invalid():
    result = lint_python("def broken(\n")
    assert "Syntax errors" in result


def test_search_code():
    code = "foo = 1\nbar = 2\nfoo_bar = 3\n"
    result = search_code(code, "foo")
    assert "Line 1" in result
    assert "Line 3" in result


def test_search_code_no_match():
    result = search_code("x = 1", "zzz")
    assert "No matches" in result


def test_count_complexity_simple():
    result = count_complexity("def f():\n    return 1\n")
    assert "complexity: 1" in result


def test_count_complexity_branching():
    code = "def f(x):\n    if x:\n        return 1\n    elif x > 5:\n        return 2\n    return 0\n"
    result = count_complexity(code)
    assert "complexity: 3" in result


def test_read_file(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("hello\n")
    result = read_file(str(f))
    assert "hello" in result


def test_read_file_not_found():
    result = read_file("/nonexistent/file.py")
    assert "not found" in result.lower()
