"""Tests for prompt templates."""

from devai.prompts import ALL_TEMPLATES, CODE_REVIEW, DEBUG, PromptTemplate


def test_prompt_template_format():
  prompt = CODE_REVIEW(language="python", code="x = 1")
  assert "python" in prompt
  assert "x = 1" in prompt


def test_prompt_template_callable():
  prompt = DEBUG(language="python", code="x[10]", error="IndexError")
  assert "IndexError" in prompt


def test_all_templates_registered():
  assert len(ALL_TEMPLATES) >= 10
  assert "code_review" in ALL_TEMPLATES
  assert "debug" in ALL_TEMPLATES


def test_custom_template():
  t = PromptTemplate(name="custom", template="Hello $name")
  assert t.format(name="World") == "Hello World"
