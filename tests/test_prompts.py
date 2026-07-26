"""Tests for prompt templates."""

import pytest

from devai.prompts import ALL_PROMPTS, CODE_REVIEW, PromptTemplate


def test_prompt_format():
    result = CODE_REVIEW.format(language="python", code="x = 1")
    assert "python" in result
    assert "x = 1" in result


def test_prompt_missing_variable():
    with pytest.raises(KeyError):
        CODE_REVIEW.format(language="python")


def test_prompt_partial():
    partial = CODE_REVIEW.partial(language="rust")
    result = partial.format(code="fn main() {}")
    assert "rust" in result


def test_all_prompts_registered():
    assert len(ALL_PROMPTS) >= 10
    assert "code_review" in ALL_PROMPTS
    assert "debug" in ALL_PROMPTS


def test_prompt_variables():
    tmpl = PromptTemplate("Hello {name}, your {thing} is ready.")
    assert tmpl.variables == {"name", "thing"}
