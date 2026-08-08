"""Tests for DevWorkflow orchestration."""

import pytest

from devai import CodeAssistant, DevWorkflow, MockLLMClient
from devai.presets import get_preset


class TestDevWorkflow:
    def test_sequential_presets(self):
        client = MockLLMClient(default_response="ok")
        assistant = CodeAssistant(client=client)
        workflow = (
            DevWorkflow("audit", assistant)
            .add("precommit", "pre-commit")
            .add("security", "security-deep-dive")
        )
        result = workflow.run(
            {
                "code": "def foo(): pass",
                "dependencies": "requests==2.0",
                "dockerfile": "FROM python:3.12",
            }
        )
        assert len(result.steps) == 2
        assert result.steps[0].name == "precommit"
        assert result.steps[1].name == "security"
        assert "precommit" in result.context

    def test_from_presets(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="ok"))
        workflow = DevWorkflow.from_presets("quick", assistant, "hotfix", "docs-gen")
        result = workflow.run({"code": "x = 1", "project": "demo", "description": "A demo"})
        assert len(result.steps) == 2
        assert result.steps[0].program_name == "hotfix"

    def test_parallel_execution(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="parallel"))
        workflow = DevWorkflow("parallel-audit", assistant).add_parallel(
            "checks",
            ("review", "pre-commit"),
            ("hotfix", "hotfix"),
        )
        result = workflow.run({"code": "def bar(): return 1"})
        assert len(result.steps) == 2
        assert all(step.parallel_group == "checks" for step in result.steps)

    def test_on_step_callback(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="cb"))
        seen: list[str] = []
        workflow = (
            DevWorkflow("cb-test", assistant)
            .add("step1", get_preset("hotfix", assistant))
            .on_step(lambda step, _ctx: seen.append(step.name))
        )
        workflow.run({"code": "pass"})
        assert seen == ["step1"]

    def test_summarize(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="summary"))
        workflow = DevWorkflow("sum", assistant).add("one", "hotfix")
        result = workflow.run({"code": "x"})
        text = result.summarize()
        assert "# Workflow: sum" in text
        assert "## one" in text

    @pytest.mark.asyncio
    async def test_arun(self):
        assistant = CodeAssistant(client=MockLLMClient(default_response="async"))
        workflow = DevWorkflow("async", assistant).add("step", "hotfix")
        result = await workflow.arun({"code": "async test"})
        assert len(result.steps) == 1
        assert result.duration_seconds >= 0
