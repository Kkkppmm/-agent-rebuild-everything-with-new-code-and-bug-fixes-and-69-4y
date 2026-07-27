"""Tests for DevAI pipeline."""

import pytest

from devai import CodeAssistant
from devai.core import MockLLMClient
from devai.pipeline import DevPipeline, PipelineStep


class TestDevPipeline:
    def test_single_step(self):
        client = MockLLMClient(default_response="Review done")
        assistant = CodeAssistant(client=client)
        pipeline = DevPipeline(assistant).add(PipelineStep.REVIEW)
        results = pipeline.run("def foo(): pass")
        assert len(results) == 1
        assert results[0].step == "review"

    def test_multiple_steps(self):
        client = MockLLMClient(
            responses=["Review", "Security", "Docstring", "Tests"]
        )
        assistant = CodeAssistant(client=client)
        pipeline = DevPipeline(assistant).full_audit()
        results = pipeline.run("code")
        assert len(results) == 4

    def test_review_then_secure(self):
        client = MockLLMClient(responses=["Review", "Security"])
        assistant = CodeAssistant(client=client)
        pipeline = DevPipeline(assistant).review_then_secure()
        results = pipeline.run("code")
        assert len(results) == 2
        assert results[0].step == "review"
        assert results[1].step == "security"

    def test_run_and_summarize(self):
        client = MockLLMClient(default_response="Output")
        assistant = CodeAssistant(client=client)
        pipeline = DevPipeline(assistant).add(PipelineStep.EXPLAIN)
        summary = pipeline.run_and_summarize("code")
        assert "Explain" in summary

    def test_chaining_add(self):
        pipeline = DevPipeline(CodeAssistant(client=MockLLMClient()))
        result = pipeline.add("review").add("security")
        assert result is pipeline
        assert len(pipeline.steps) == 2

    @pytest.mark.asyncio
    async def test_arun(self):
        client = MockLLMClient(default_response="async review")
        assistant = CodeAssistant(client=client)
        pipeline = DevPipeline(assistant).add(PipelineStep.REVIEW)
        results = await pipeline.arun("def bar(): pass")
        assert len(results) == 1
        assert results[0].output == "async review"
