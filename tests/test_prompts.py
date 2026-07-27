"""Tests for prompts."""

from devai.prompts import CODE_REVIEW, DEBUG_CODE, PromptTemplate


def test_prompt_template():
    t = PromptTemplate("Hello $name!")
    assert t.format(name="World") == "Hello World!"


def test_code_review_prompt():
    result = CODE_REVIEW.format(language="python", code="x = 1")
    assert "python" in result
    assert "x = 1" in result


def test_debug_prompt():
    result = DEBUG_CODE.format(language="python", code="x=1", error="NameError")
    assert "NameError" in result
