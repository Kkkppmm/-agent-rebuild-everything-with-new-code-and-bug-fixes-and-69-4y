"""Tests for prompt templates."""

import pytest

from devai.prompts import (
    ALL_TEMPLATES,
    CODE_REVIEW,
    DEBUG,
    PromptTemplate,
    get_template,
)


class TestPromptTemplate:
    def test_render(self):
        result = CODE_REVIEW.render(language="python", code="x = 1")
        assert "python" in result
        assert "x = 1" in result

    def test_to_messages(self):
        msgs = DEBUG.to_messages(error="err", code="c", context="ctx")
        assert len(msgs) == 2
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"

    def test_custom_template(self):
        t = PromptTemplate(name="test", template="Hello $name")
        assert t.render(name="World") == "Hello World"

    def test_all_templates_registered(self):
        assert len(ALL_TEMPLATES) >= 13

    def test_get_template(self):
        t = get_template("code_review")
        assert t is CODE_REVIEW

    def test_get_template_unknown(self):
        with pytest.raises(KeyError, match="Unknown template"):
            get_template("nonexistent")
