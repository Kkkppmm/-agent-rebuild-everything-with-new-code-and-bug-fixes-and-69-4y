"""Tests for DevAI programs."""

import json

import pytest

from devai import CodeAssistant, DevProgram, ProgramTask
from devai.core import MockLLMClient


class TestProgramTask:
    def test_from_dict(self):
        task = ProgramTask.from_dict(
            {"name": "review", "action": "review", "input_key": "code", "kwargs": {"x": 1}}
        )
        assert task.name == "review"
        assert task.action == "review"
        assert task.kwargs == {"x": 1}

    def test_to_dict(self):
        task = ProgramTask(name="step", action="explain")
        data = task.to_dict()
        assert data["name"] == "step"
        assert data["action"] == "explain"


class TestDevProgram:
    def test_add_and_run(self):
        client = MockLLMClient(responses=["Review output", "Security output"])
        assistant = CodeAssistant(client=client)
        program = (
            DevProgram("audit", assistant)
            .add("review_step", "review")
            .add("security_step", "security")
        )
        results = program.run({"code": "def foo(): pass"})
        assert len(results) == 2
        assert results[0].name == "review_step"
        assert results[1].action == "security"

    def test_chained_context(self):
        client = MockLLMClient(default_response="Explained")
        assistant = CodeAssistant(client=client)
        program = DevProgram("chain", assistant).add("explain", "explain")
        program.run({"code": "x = 1"})
        context = {"code": "x = 1"}
        results = program.run(context)
        assert "explain" in context
        assert results[0].output == "Explained"

    def test_from_dict_and_json(self):
        data = {
            "name": "quick-review",
            "tasks": [{"name": "review", "action": "review"}],
        }
        assistant = CodeAssistant(client=MockLLMClient(default_response="ok"))
        program = DevProgram.from_dict(data, assistant)
        assert program.name == "quick-review"
        assert len(program.tasks) == 1

        loaded = DevProgram.from_json(json.dumps(data), assistant)
        assert loaded.to_dict() == data

    def test_save_and_load(self, tmp_path):
        assistant = CodeAssistant(client=MockLLMClient())
        program = DevProgram("saved", assistant).add("review", "review")
        path = tmp_path / "program.json"
        program.save(path)
        loaded = DevProgram.from_file(path, assistant)
        assert loaded.name == "saved"
        assert len(loaded.tasks) == 1

    def test_run_and_summarize(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="done"))
        program = DevProgram("summary", assistant).add("review", "review")
        summary = program.run_and_summarize({"code": "pass"})
        assert "review" in summary
        assert "done" in summary

    def test_unsupported_action(self):
        assistant = CodeAssistant(client=MockLLMClient())
        program = DevProgram("bad", assistant)
        with pytest.raises(ValueError, match="Unsupported action"):
            program.add("x", "not_real")

    @pytest.mark.asyncio
    async def test_arun(self):
        client = MockLLMClient(default_response="async review")
        assistant = CodeAssistant(client=client)
        program = DevProgram("async", assistant).add("review", "review")
        results = await program.arun({"code": "def bar(): pass"})
        assert results[0].output == "async review"

    def test_from_yaml(self, tmp_path):
        pytest.importorskip("yaml")
        assistant = CodeAssistant(client=MockLLMClient(default_response="yaml ok"))
        yaml_text = """
name: yaml-program
tasks:
  - name: review
    action: review
"""
        program = DevProgram.from_yaml(yaml_text, assistant)
        assert program.name == "yaml-program"
        results = program.run({"code": "x = 1"})
        assert results[0].output == "yaml ok"

        path = tmp_path / "program.yaml"
        path.write_text(yaml_text)
        loaded = DevProgram.from_file(path, assistant)
        assert loaded.name == "yaml-program"

    def test_openapi_action(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="openapi spec"))
        program = DevProgram("api", assistant).add("spec", "openapi")
        results = program.run({"code": "class UserAPI: pass"})
        assert results[0].output == "openapi spec"

    def test_code_smell_action(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="smells found"))
        program = DevProgram("smells", assistant).add("smells", "code_smell")
        results = program.run({"code": "def huge(): pass"})
        assert results[0].output == "smells found"
