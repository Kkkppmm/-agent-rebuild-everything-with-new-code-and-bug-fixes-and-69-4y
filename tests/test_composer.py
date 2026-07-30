"""Tests for DevAI program composer."""

from devai.composer import ProgramComposer
from devai.core import MockLLMClient
from devai.assistant import CodeAssistant


class TestProgramComposer:
    def test_from_presets(self):
        assistant = CodeAssistant(client=MockLLMClient())
        composer = ProgramComposer.from_presets(assistant, ["pre-commit", "release"])
        assert composer.task_count > 4

    def test_add_task(self):
        assistant = CodeAssistant(client=MockLLMClient())
        composer = ProgramComposer(assistant, name="custom")
        composer.add_task("lint", "fix_lint", input_key="code")
        program = composer.build()
        assert program.name == "custom"
        assert len(program.tasks) == 1
        assert program.tasks[0].action == "fix_lint"

    def test_dedupe_actions(self):
        assistant = CodeAssistant(client=MockLLMClient())
        composer = ProgramComposer.from_presets(assistant, ["pre-commit", "release"])
        before = composer.task_count
        composer.dedupe_actions()
        assert composer.task_count < before

    def test_describe(self):
        assistant = CodeAssistant(client=MockLLMClient())
        composer = ProgramComposer.from_presets(assistant, ["pre-commit"])
        text = composer.describe()
        assert "pre-commit" in text
        assert "review" in text

    def test_with_prefix(self):
        assistant = CodeAssistant(client=MockLLMClient())
        composer = ProgramComposer.from_presets(assistant, ["pre-commit"])
        composer.with_prefix("a")
        program = composer.build()
        assert all(t.name.startswith("a_") for t in program.tasks)
