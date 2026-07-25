"""Tests for DevAI prompts."""

import pytest

from devai.prompts.template import PromptTemplate
from devai.prompts import CODE_REVIEW, DEBUG, COMMIT_MESSAGE, API_DESIGN


class TestPromptTemplate:
    def test_format(self):
        t = PromptTemplate("Hello {name}, you have {count} messages.")
        assert t.format(name="Alice", count=3) == "Hello Alice, you have 3 messages."

    def test_variables(self):
        t = PromptTemplate("Review {language} code: {code}")
        assert t.variables == {"language", "code"}

    def test_missing_variable_raises(self):
        t = PromptTemplate("Hello {name}")
        with pytest.raises(KeyError):
            t.format()

    def test_partial_mode(self):
        t = PromptTemplate("Hello {name}", partial=True)
        assert t.format() == "Hello {name}"

    def test_chain_with_or(self):
        t1 = PromptTemplate("Step 1: {task}")
        t2 = PromptTemplate("Step 2: review output")
        combined = t1 | t2
        assert "Step 1" in combined.template
        assert "Step 2" in combined.template


class TestDevPrompts:
    def test_code_review(self):
        result = CODE_REVIEW.format(code="x=1", language="python")
        assert "python" in result
        assert "x=1" in result

    def test_debug(self):
        result = DEBUG.format(
            language="python", error="NameError", code="print(x)", context="testing"
        )
        assert "NameError" in result

    def test_commit_message(self):
        result = COMMIT_MESSAGE.format(diff="+ added feature")
        assert "diff" in result.lower() or "added feature" in result

    def test_api_design(self):
        result = API_DESIGN.format(requirement="user auth", stack="FastAPI")
        assert "FastAPI" in result
