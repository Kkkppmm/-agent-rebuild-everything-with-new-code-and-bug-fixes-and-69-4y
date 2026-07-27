"""Tests for prompt templates."""

from devai.prompts.templates import PromptTemplate
from devai.prompts import dev_prompts


def test_format_basic():
    tmpl = PromptTemplate("Hello {name}!")
    assert tmpl.format(name="World") == "Hello World!"


def test_format_missing_vars_default_empty():
    tmpl = PromptTemplate("Code: {code}\n{context}")
    result = tmpl.format(code="def foo(): pass")
    assert "def foo(): pass" in result
    assert "context" not in result.lower() or result.endswith("\n")


def test_variables():
    tmpl = PromptTemplate("Review {code} with {context}")
    assert tmpl.variables == {"code", "context"}


def test_partial():
    tmpl = PromptTemplate("Review {code} with {context}")
    partial = tmpl.partial(code="x = 1")
    result = partial.format(context="testing")
    assert "x = 1" in result
    assert "testing" in result


def test_dev_prompts_have_placeholders():
    assert "{code}" in dev_prompts.CODE_REVIEW
    assert "{error}" in dev_prompts.DEBUG
    assert "{diff}" in dev_prompts.COMMIT_MESSAGE
    assert "{code}" in dev_prompts.SECURITY_REVIEW


def test_code_review_prompt():
    prompt = PromptTemplate(dev_prompts.CODE_REVIEW).format(code="def foo(): pass", context="")
    assert "def foo(): pass" in prompt
    assert "code reviewer" in prompt.lower()
