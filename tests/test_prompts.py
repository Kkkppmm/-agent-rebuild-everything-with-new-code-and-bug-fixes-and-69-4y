"""Tests for prompt templates."""

import pytest
from devai.prompts.template import PromptTemplate
from devai.prompts.dev_prompts import CODE_REVIEW, DEBUG, COMMIT_MESSAGE


def test_format():
    t = PromptTemplate("Hello {name}, you have {count} messages.")
    assert t.format(name="Alice", count=5) == "Hello Alice, you have 5 messages."


def test_missing_variable():
    t = PromptTemplate("Hello {name}")
    with pytest.raises(KeyError):
        t.format()


def test_variables_property():
    t = PromptTemplate("{a} and {b}")
    assert t.variables == {"a", "b"}


def test_partial():
    t = PromptTemplate("{a} {b} {c}")
    partial = t.partial(a="1", b="2")
    assert partial.format(c="3") == "1 2 3"


def test_code_review_template():
    result = CODE_REVIEW.format(
        code="def f(): pass",
        language="python",
        context="test",
    )
    assert "def f(): pass" in result
    assert "python" in result


def test_debug_template():
    result = DEBUG.format(
        error="ValueError",
        code="x = int('a')",
        language="python",
        stack_trace="line 1",
    )
    assert "ValueError" in result


def test_commit_message_template():
    result = COMMIT_MESSAGE.format(diff="+ added feature")
    assert "added feature" in result
