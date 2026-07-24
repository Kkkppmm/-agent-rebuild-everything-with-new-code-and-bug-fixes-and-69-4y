"""Tests for DevAI prompts."""

import pytest

from devai.prompts import PromptTemplate, CODE_REVIEW, DEBUG, COMMIT_MESSAGE


class TestPromptTemplate:
    def test_format(self):
        tmpl = PromptTemplate("Hello {name}, you have {count} messages.")
        result = tmpl.format(name="Alice", count=5)
        assert result == "Hello Alice, you have 5 messages."

    def test_missing_variable(self):
        tmpl = PromptTemplate("Hello {name}")
        with pytest.raises(KeyError):
            tmpl.format()

    def test_variables(self):
        tmpl = PromptTemplate("Review {code} in {language}")
        assert tmpl.variables == {"code", "language"}

    def test_partial(self):
        tmpl = PromptTemplate("Review {code} in {language}")
        partial = tmpl.partial(language="python")
        result = partial.format(code="def foo(): pass")
        assert "python" in result
        assert "def foo(): pass" in result


class TestDevPrompts:
    def test_code_review_has_variables(self):
        tmpl = PromptTemplate(CODE_REVIEW)
        assert "code" in tmpl.variables
        assert "language" in tmpl.variables

    def test_debug_has_variables(self):
        tmpl = PromptTemplate(DEBUG)
        assert "error" in tmpl.variables
        assert "code" in tmpl.variables

    def test_commit_message(self):
        tmpl = PromptTemplate(COMMIT_MESSAGE)
        result = tmpl.format(diff="+ added feature")
        assert "added feature" in result
