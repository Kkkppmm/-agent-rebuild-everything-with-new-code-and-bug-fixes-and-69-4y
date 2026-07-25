"""Tests for prompt templates."""


from devai.core.models import Role
from devai.prompts import dev
from devai.prompts.template import PromptTemplate


def test_prompt_format():
    template = PromptTemplate("Hello, {name}!")
    assert template.format(name="World") == "Hello, World!"


def test_prompt_missing_variables():
    template = PromptTemplate("Hello, {name}!")
    assert template.missing_variables() == {"name"}
    assert template.missing_variables({"name": "Dev"}) == set()


def test_prompt_to_messages():
    template = PromptTemplate("Fix: {bug}", system="You are a debugger.")
    messages = template.to_messages(bug="null pointer")
    assert len(messages) == 2
    assert messages[0].role == Role.SYSTEM
    assert messages[1].content == "Fix: null pointer"


def test_dev_prompts_have_placeholders():
    assert "code" in dev.CODE_REVIEW.template
    assert dev.CODE_REVIEW.system is not None
