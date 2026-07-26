"""Tests for prompt templates."""

from devai.prompts import (
    CODE_REVIEW,
    COMMIT_MESSAGE,
    DEBUG,
    EXPLAIN_CODE,
    PromptTemplate,
    REFACTOR,
    SECURITY_REVIEW,
    TEST_GEN,
)


class TestPromptTemplate:
    def test_format(self):
        tmpl = PromptTemplate(template="Hello ${name}!")
        assert tmpl.format(name="World") == "Hello World!"

    def test_to_messages_with_system(self):
        tmpl = PromptTemplate(template="Do ${task}", system="You are helpful.")
        msgs = tmpl.to_messages(task="review")
        assert len(msgs) == 2
        assert msgs[0]["role"] == "system"
        assert msgs[1]["content"] == "Do review"

    def test_code_review(self):
        result = CODE_REVIEW.format(code="x = 1", language="python")
        assert "x = 1" in result
        assert "python" in result

    def test_debug(self):
        result = DEBUG.format(error="TypeError", code_section="")
        assert "TypeError" in result

    def test_commit_message(self):
        result = COMMIT_MESSAGE.format(diff="+ added feature")
        assert "added feature" in result

    def test_security_review(self):
        result = SECURITY_REVIEW.format(code="eval(input())")
        assert "eval" in result

    def test_refactor(self):
        result = REFACTOR.format(code="pass", goals="simplify")
        assert "simplify" in result

    def test_test_gen(self):
        result = TEST_GEN.format(code="def add(a, b): return a + b")
        assert "add" in result

    def test_explain_code(self):
        result = EXPLAIN_CODE.format(code="print(1)", language="python")
        assert "print" in result
