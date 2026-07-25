"""Tests for PromptTemplate."""

import pytest

from devai.prompts import CODE_REVIEW, DEBUG_ERROR, EXPLAIN_CODE, COMMIT_MESSAGE
from devai.prompts.template import PromptTemplate


def test_format_template():
    tpl = PromptTemplate("Hello {name}, write {language} code.")
    result = tpl.format(name="dev", language="Python")
    assert "Hello dev" in result
    assert "Python" in result


def test_auto_detect_variables():
    tpl = PromptTemplate("Fix {error} in {file}")
    assert tpl.input_variables == ["error", "file"]


def test_missing_variable_raises():
    tpl = PromptTemplate("Hello {name}")
    with pytest.raises(KeyError, match="Missing template variables"):
        tpl.format()


def test_code_review_template():
    result = CODE_REVIEW.format(language="python", code="x = 1")
    assert "python" in result
    assert "x = 1" in result


def test_debug_template():
    result = DEBUG_ERROR.format(error="NameError", code="print(x)")
    assert "NameError" in result


def test_explain_template():
    result = EXPLAIN_CODE.format(language="rust", code="fn main() {}")
    assert "rust" in result


def test_commit_message_template():
    result = COMMIT_MESSAGE.format(diff="+ added feature")
    assert "conventional commit" in result.lower()
