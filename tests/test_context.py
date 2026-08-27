"""Tests for DevContext and PromptBuilder."""

from __future__ import annotations

from pathlib import Path

import pytest

from devai.context import DevContext, PromptBuilder
from devai.core.models import Message


class TestDevContext:
    def test_empty_build(self):
        assert DevContext().build() == ""

    def test_text_section(self):
        ctx = DevContext().text("hello world", label="Greeting")
        result = ctx.build()
        assert "### Greeting" in result
        assert "hello world" in result

    def test_snippet_with_language(self):
        ctx = DevContext().snippet("x = 1", language="python", label="Code")
        result = ctx.build()
        assert "```python" in result
        assert "x = 1" in result

    def test_file_section(self, tmp_path: Path):
        src = tmp_path / "main.py"
        src.write_text("print('hi')\n")
        ctx = DevContext().with_base(tmp_path).file("main.py")
        result = ctx.build()
        assert "print('hi')" in result
        assert "main.py" in result

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            DevContext().file("/nonexistent/file.py")

    def test_files_multiple(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("a = 1\n")
        (tmp_path / "b.py").write_text("b = 2\n")
        ctx = DevContext().with_base(tmp_path).files(["a.py", "b.py"])
        result = ctx.build()
        assert "a = 1" in result
        assert "b = 2" in result

    def test_vars_interpolation(self):
        ctx = DevContext().text("Task: ${var:task}").vars(task="review")
        assert "Task: review" in ctx.build()

    def test_env_section(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "secret")
        ctx = DevContext().env("MY_VAR")
        assert "secret" in ctx.build()

    def test_git_diff_empty(self, monkeypatch):
        monkeypatch.setattr("devai.context.get_git_diff", lambda **kwargs: "")
        ctx = DevContext().git_diff()
        assert ctx.build() == ""

    def test_git_diff_with_content(self, monkeypatch):
        monkeypatch.setattr(
            "devai.context.get_git_diff",
            lambda **kwargs: "diff --git a/foo.py b/foo.py\n+print('hi')",
        )
        ctx = DevContext().git_diff()
        result = ctx.build()
        assert "### Git diff" in result
        assert "foo.py" in result

    def test_token_count(self):
        ctx = DevContext().text("hello " * 100)
        assert ctx.token_count() > 0

    def test_max_tokens_truncation(self):
        ctx = DevContext().text("word " * 500).with_max_tokens(10)
        result = ctx.build()
        assert len(result) < 500

    def test_to_messages_with_context(self):
        ctx = DevContext().snippet("def f(): pass", label="Code")
        messages = ctx.to_messages("Review this", system="You are helpful")
        assert len(messages) == 2
        assert messages[0].role == "system"
        assert "Context:" in messages[1].content
        assert "Review this" in messages[1].content

    def test_to_messages_no_context(self):
        messages = DevContext().to_messages("Just a question")
        assert len(messages) == 1
        assert messages[0].content == "Just a question"

    def test_to_dict(self):
        ctx = DevContext().snippet("x = 1").vars(foo="bar")
        d = ctx.to_dict()
        assert len(d["sections"]) == 1
        assert d["variables"] == {"foo": "bar"}
        assert d["token_count"] > 0

    def test_from_files(self, tmp_path: Path):
        (tmp_path / "x.py").write_text("x = 1\n")
        ctx = DevContext.from_files(["x.py"], base_path=tmp_path)
        assert "x = 1" in ctx.build()

    def test_fluent_chaining(self):
        ctx = (
            DevContext()
            .text("notes")
            .snippet("pass")
            .vars(k="v")
        )
        result = ctx.build()
        assert "notes" in result
        assert "pass" in result


class TestPromptBuilder:
    def test_system_and_user(self):
        messages = PromptBuilder().system("Be concise").user("Hello").build()
        assert len(messages) == 2
        assert messages[0] == Message.system("Be concise")
        assert messages[1].content == "Hello"

    def test_context_prepended(self):
        ctx = DevContext().snippet("def f(): pass", label="Code")
        messages = (
            PromptBuilder()
            .system("Reviewer")
            .context(ctx)
            .user("Find bugs")
            .build()
        )
        assert len(messages) == 2
        assert "Context:" in messages[1].content
        assert "Find bugs" in messages[1].content

    def test_few_shot_example(self):
        messages = (
            PromptBuilder()
            .example("2+2?", "4")
            .user("3+3?")
            .build()
        )
        assert len(messages) == 3
        assert messages[0].content == "2+2?"
        assert messages[1].content == "4"
        assert messages[2].content == "3+3?"

    def test_build_string(self):
        text = PromptBuilder().system("sys").user("usr").build_string()
        assert "[SYSTEM]" in text
        assert "[USER]" in text
        assert "sys" in text
        assert "usr" in text

    def test_context_with_var_interpolation(self):
        ctx = DevContext().vars(severity="high")
        messages = (
            PromptBuilder()
            .context(ctx)
            .user("Severity: ${var:severity}")
            .build()
        )
        assert "Severity: high" in messages[0].content
