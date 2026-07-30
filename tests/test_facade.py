"""Tests for the DevAI facade."""

from devai import DevAI
from devai.runtime import DevRuntime


class TestDevAI:
    def test_mock_factory(self):
        ai = DevAI.mock()
        assert isinstance(ai, DevAI)
        assert isinstance(ai.runtime, DevRuntime)
        assert ai.review("def add(a, b): return a + b")

    def test_delegates_assistant(self):
        ai = DevAI.mock()
        assert ai.assistant is ai.runtime.assistant

    def test_explain_and_generate(self):
        ai = DevAI.mock()
        assert ai.explain("x = 1")
        assert ai.generate("a function that adds two numbers")

    def test_debug_and_refactor(self):
        ai = DevAI.mock()
        assert ai.debug("x = 1", "NameError")
        assert ai.refactor("x=1")

    def test_run_preset_dry_run(self):
        ai = DevAI.mock()
        steps = ai.dry_run("pre-commit")
        assert len(steps) >= 1

    def test_preset_returns_program(self):
        ai = DevAI.mock()
        program = ai.preset("pre-commit")
        assert program.name

    def test_workflow(self):
        ai = DevAI.mock()
        wf = ai.workflow("test")
        assert wf.name == "test"

    def test_getattr_delegates_to_runtime(self):
        ai = DevAI.mock()
        assert ai.kit is ai.runtime.kit
        assert ai.config is ai.runtime.config

    def test_scaffold(self, tmp_path):
        result = DevAI.scaffold(tmp_path, include_schedule=False, include_starter=False)
        assert result.ok
        assert (tmp_path / ".devai.yaml").is_file()
        assert (tmp_path / "programs" / "pre-commit.yaml").is_file()
