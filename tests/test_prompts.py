"""Tests for prompt templates."""

import pytest

from devai.prompts.template import PromptTemplate
from devai.prompts import dev_prompts


def test_prompt_format():
    t = PromptTemplate("Hello {name}, write {language} code.")
    result = t.format(name="Alice", language="Python")
    assert "Alice" in result
    assert "Python" in result


def test_prompt_missing_variable():
    t = PromptTemplate("Hello {name}")
    with pytest.raises(KeyError):
        t.format()


def test_prompt_variables():
    t = PromptTemplate("{a} and {b}")
    assert t.variables == {"a", "b"}


def test_prompt_partial():
    t = PromptTemplate("Hello {name}, language: {lang}")
    partial = t.partial(name="Bob")
    result = partial.format(lang="Rust")
    assert "Bob" in result
    assert "Rust" in result


def test_dev_prompts_exist():
    assert len(dev_prompts.ALL_PROMPTS) >= 10


def test_code_review_prompt():
    result = dev_prompts.CODE_REVIEW.format(code="x=1", language="python")
    assert "x=1" in result
    assert "python" in result


def test_debug_prompt():
    result = dev_prompts.DEBUG.format(code="pass", error="NameError", language="python")
    assert "NameError" in result
