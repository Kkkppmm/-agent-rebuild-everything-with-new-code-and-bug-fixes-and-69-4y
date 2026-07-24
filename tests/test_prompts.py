"""Tests for prompt templates."""

from devai.prompts import (
    CODE_REVIEW,
    COMMIT_MESSAGE,
    DEBUG,
    EXPLAIN_CODE,
    REFACTOR,
    SECURITY_REVIEW,
    PromptTemplate,
)


def test_prompt_template_format():
    tpl = PromptTemplate("Hello {name}!")
    assert tpl.format(name="world") == "Hello world!"
    assert tpl(name="dev") == "Hello dev!"


def test_code_review_prompt():
    result = CODE_REVIEW.format(code="def foo(): pass", language="python")
    assert "def foo(): pass" in result
    assert "python" in result


def test_debug_prompt():
    result = DEBUG.format(code="x=1", error="NameError", language="python")
    assert "NameError" in result
    assert "x=1" in result


def test_commit_message_prompt():
    result = COMMIT_MESSAGE.format(diff="+ added feature")
    assert "added feature" in result


def test_security_review_prompt():
    result = SECURITY_REVIEW.format(code="eval(x)", language="python")
    assert "eval(x)" in result


def test_refactor_prompt():
    result = REFACTOR.format(code="a=1", language="python", goals="simplify")
    assert "simplify" in result


def test_explain_code_prompt():
    result = EXPLAIN_CODE.format(code="pass", language="python")
    assert "pass" in result
