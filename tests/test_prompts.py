"""Tests for DevAI prompts."""

import pytest

from devai.prompts.template import PromptTemplate
from devai.prompts import dev


def test_prompt_template_format():
    tpl = PromptTemplate("Hello {name}, write {language} code.")
    result = tpl.format(name="Alice", language="Python")
    assert "Alice" in result
    assert "Python" in result


def test_prompt_template_missing_var():
    tpl = PromptTemplate("Hello {name}")
    with pytest.raises(KeyError):
        tpl.format()


def test_prompt_template_partial():
    tpl = PromptTemplate("Review {language} code: {code}")
    partial = tpl.partial(language="python")
    result = partial.format(code="pass")
    assert "python" in result
    assert "pass" in result


def test_code_review_prompt():
    result = dev.CODE_REVIEW.format(language="python", code="x = 1")
    assert "python" in result
    assert "x = 1" in result


def test_debug_prompt():
    result = dev.DEBUG.format(error="NameError", language="python", code="print(x)")
    assert "NameError" in result
