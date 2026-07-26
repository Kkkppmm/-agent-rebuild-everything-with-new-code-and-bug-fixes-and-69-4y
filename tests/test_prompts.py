"""Tests for prompts module."""

import pytest

from devai.prompts.template import PromptTemplate
from devai.prompts import ALL_PROMPTS, CODE_REVIEW, DEBUG


class TestPromptTemplate:
    def test_format(self):
        t = PromptTemplate(template="Hello {name}!", input_variables=["name"])
        assert t.format(name="World") == "Hello World!"

    def test_auto_extract_variables(self):
        t = PromptTemplate(template="Review {language} code: {code}")
        assert set(t.input_variables) == {"language", "code"}

    def test_missing_variable_raises(self):
        t = PromptTemplate(template="Hello {name}")
        with pytest.raises(KeyError):
            t.format()

    def test_partial(self):
        t = PromptTemplate(template="Hello {name}, welcome to {place}")
        partial = t.partial(name="Alice")
        assert partial.format(place="Wonderland") == "Hello Alice, welcome to Wonderland"


class TestDevPrompts:
    def test_all_prompts_registered(self):
        assert len(ALL_PROMPTS) >= 10

    def test_code_review_format(self):
        result = CODE_REVIEW.format(language="python", code="x = 1")
        assert "python" in result
        assert "x = 1" in result

    def test_debug_format(self):
        result = DEBUG.format(error="TypeError", code="x = 'a' + 1")
        assert "TypeError" in result
