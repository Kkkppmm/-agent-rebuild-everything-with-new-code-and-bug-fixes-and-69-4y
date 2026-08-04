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

    def test_from_yaml(self, tmp_path):
        yaml_content = """
name: yaml-program
tasks:
  - name: review
    action: review
"""
        path = tmp_path / "program.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        assistant = CodeAssistant(client=MockLLMClient())
        program = DevProgram.from_file(path, assistant)
        assert program.name == "yaml-program"
        assert program.tasks[0].action == "review"

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

    def test_resolve_context_kwargs(self):
        client = MockLLMClient(default_response="triaged")
        assistant = CodeAssistant(client=client)
        program = DevProgram("triage", assistant).add(
            "triage",
            "incident_triage",
            input_key="symptoms",
            logs="$logs",
        )
        results = program.run({"symptoms": "errors", "logs": "traceback"})
        assert results[0].output == "triaged"

    def test_to_yaml_and_save(self, tmp_path):
        assistant = CodeAssistant(client=MockLLMClient())
        program = DevProgram("yaml-out", assistant).add("review", "review")
        yaml_text = program.to_yaml()
        assert "yaml-out" in yaml_text
        assert "review" in yaml_text

        path = tmp_path / "program.yaml"
        program.save(path)
        loaded = DevProgram.from_file(path, assistant)
        assert loaded.name == "yaml-out"
        assert len(loaded.tasks) == 1

    def test_compose(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="ok"))
        review = DevProgram("review-only", assistant).add("review", "review")
        security = DevProgram("security-only", assistant).add("security", "security")
        merged = DevProgram.compose(review, security, name="full-audit")
        assert merged.name == "full-audit"
        assert len(merged.tasks) == 2
        assert merged.tasks[0].action == "review"
        assert merged.tasks[1].action == "security"

    def test_compose_requires_shared_assistant(self):
        a1 = CodeAssistant(client=MockLLMClient())
        a2 = CodeAssistant(client=MockLLMClient())
        p1 = DevProgram("one", a1).add("review", "review")
        p2 = DevProgram("two", a2).add("security", "security")
        with pytest.raises(ValueError, match="same CodeAssistant"):
            DevProgram.compose(p1, p2)

    def test_from_inline_dict(self):
        data = {"name": "inline", "tasks": [{"name": "review", "action": "review"}]}
        assistant = CodeAssistant(client=MockLLMClient(default_response="inline ok"))
        program = DevProgram.from_inline(data, assistant)
        assert program.name == "inline"
        results = program.run({"code": "x = 1"})
        assert results[0].output == "inline ok"

    def test_from_inline_json_text(self):
        text = '{"name": "json-inline", "tasks": [{"name": "review", "action": "review"}]}'
        assistant = CodeAssistant(client=MockLLMClient(default_response="json ok"))
        program = DevProgram.from_inline(text, assistant)
        assert program.name == "json-inline"
        results = program.run({"code": "pass"})
        assert results[0].output == "json ok"

    def test_from_text_yaml(self):
        yaml_text = """name: text-yaml
tasks:
  - name: review
    action: review
"""
        assistant = CodeAssistant(client=MockLLMClient())
        program = DevProgram.from_text(yaml_text, assistant)
        assert program.name == "text-yaml"
        assert program.tasks[0].action == "review"
