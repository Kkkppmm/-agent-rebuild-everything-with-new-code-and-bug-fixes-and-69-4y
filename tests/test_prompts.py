"""Tests for prompt templates."""

import pytest

from devai.prompts.template import PromptTemplate
from devai.prompts import dev_prompts


class TestPromptTemplate:
    def test_format(self):
        t = PromptTemplate("Hello {name}, you have {count} messages.")
        assert t.format(name="Alice", count=5) == "Hello Alice, you have 5 messages."

    def test_missing_variable_raises(self):
        t = PromptTemplate("Hello {name}")
        with pytest.raises(KeyError):
            t.format()

    def test_partial_mode(self):
        t = PromptTemplate("Hello {name}", partial=True)
        assert t.format() == "Hello "

    def test_variables_property(self):
        t = PromptTemplate("{a} and {b}")
        assert t.variables == {"a", "b"}

    def test_chain_operator(self):
        t1 = PromptTemplate("Part 1")
        t2 = PromptTemplate("Part 2")
        combined = t1 | t2
        assert "Part 1" in combined.template
        assert "Part 2" in combined.template


class TestDevPrompts:
    def test_code_review(self):
        result = dev_prompts.CODE_REVIEW.format(
            language="python", code="x=1", extra_instructions=""
        )
        assert "python" in result
        assert "x=1" in result

    def test_debug(self):
        result = dev_prompts.DEBUG.format(
            error="NameError", language="python", code="print(x)", stack_trace=""
        )
        assert "NameError" in result

    def test_commit_message(self):
        result = dev_prompts.COMMIT_MESSAGE.format(diff="+ added feature")
        assert "added feature" in result

    def test_all_prompts_have_format(self):
        prompts = [
            dev_prompts.API_DESIGN,
            dev_prompts.SECURITY_REVIEW,
            dev_prompts.SQL_OPTIMIZE,
            dev_prompts.README_GEN,
            dev_prompts.TYPE_HINTS,
            dev_prompts.REGEX_BUILD,
            dev_prompts.LOG_ANALYSIS,
            dev_prompts.EXPLAIN_CODE,
            dev_prompts.GENERATE_TESTS,
            dev_prompts.REFACTOR,
        ]
        for p in prompts:
            assert isinstance(p, PromptTemplate)
            assert len(p.variables) > 0
