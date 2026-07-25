"""Tests for prompt templates."""

import pytest

from devai.prompts.dev_prompts import CODE_REVIEW, DEBUG
from devai.prompts.template import PromptTemplate


def test_prompt_template_format():
  tpl = PromptTemplate("Hello {name}, write {language} code.")
  result = tpl.format(name="Alice", language="Python")
  assert "Alice" in result
  assert "Python" in result


def test_prompt_template_missing_var():
  tpl = PromptTemplate("Hello {name}")
  with pytest.raises(ValueError, match="Missing template variables"):
    tpl.format()


def test_prompt_template_partial():
  tpl = PromptTemplate("Hello {name}, lang={language}")
  partial = tpl.partial(name="Bob")
  result = partial.format(language="Rust")
  assert "Bob" in result
  assert "Rust" in result


def test_code_review_prompt():
  result = CODE_REVIEW.format(language="python", code="print('hi')")
  assert "python" in result
  assert "print('hi')" in result


def test_debug_prompt():
  result = DEBUG.format(language="python", error="NameError", code="x = y")
  assert "NameError" in result
