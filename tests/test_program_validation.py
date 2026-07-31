"""Tests for program validation."""

from devai import CodeAssistant, DevProgram, ProgramTask
from devai.core import MockLLMClient


class TestProgramValidation:
    def test_valid_program(self):
        assistant = CodeAssistant(client=MockLLMClient())
        program = DevProgram("ok", assistant).add("review", "review")
        assert program.is_valid()
        assert program.validate() == []

    def test_empty_tasks(self):
        assistant = CodeAssistant(client=MockLLMClient())
        program = DevProgram("empty", assistant)
        errors = program.validate()
        assert any("at least one task" in e for e in errors)

    def test_duplicate_task_names(self):
        assistant = CodeAssistant(client=MockLLMClient())
        program = (
            DevProgram("dup", assistant)
            .add("step", "review")
            .add("step", "security")
        )
        errors = program.validate()
        assert any("duplicate" in e for e in errors)

    def test_unsupported_action(self):
        assistant = CodeAssistant(client=MockLLMClient())
        program = DevProgram("bad", assistant)
        program.tasks.append(ProgramTask(name="x", action="not_real"))
        errors = program.validate()
        assert any("unsupported action" in e for e in errors)

    def test_docs_gen_preset(self):
        from devai.presets import get_preset

        assistant = CodeAssistant(client=MockLLMClient())
        program = get_preset("docs-gen", assistant)
        assert program.is_valid()
        assert len(program.tasks) == 3
