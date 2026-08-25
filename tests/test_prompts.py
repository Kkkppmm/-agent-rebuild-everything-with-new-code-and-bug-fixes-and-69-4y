"""Tests for DevAI prompts."""

import pytest

from devai.prompts import CODE_REVIEW, DEBUG, DIFF_REVIEW, EXPLAIN, PromptTemplate


class TestPromptTemplate:
    def test_format(self):
        result = CODE_REVIEW.format(code="def foo(): pass")
        assert "def foo(): pass" in result

    def test_missing_variable(self):
        with pytest.raises(ValueError, match="Missing template variables"):
            CODE_REVIEW.format()

    def test_to_messages(self):
        msgs = EXPLAIN.to_messages(code="x = 1")
        assert len(msgs) == 2
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"

    def test_custom_template(self):
        t = PromptTemplate(
            template="Hello $name",
            input_variables=["name"],
        )
        assert t.format(name="World") == "Hello World"

    def test_debug_template(self):
        result = DEBUG.format(code="x", error="NameError")
        assert "NameError" in result
        assert "x" in result

    def test_diff_review_template(self):
        result = DIFF_REVIEW.format(diff="+added line")
        assert "added line" in result
