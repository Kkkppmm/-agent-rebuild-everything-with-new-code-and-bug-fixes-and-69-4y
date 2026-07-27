"""Tests for pipeline."""

from devai import CodeAssistant, MockLLMClient
from devai.pipeline import DevPipeline


def test_pipeline_review_then_test():
    assistant = CodeAssistant(client=MockLLMClient())
    pipeline = DevPipeline(assistant).review_then_test()
    result = pipeline.run("def f(): pass")
    assert "review" in result.outputs
    assert "tests" in result.outputs


def test_pipeline_debug_then_fix():
    assistant = CodeAssistant(client=MockLLMClient())
    pipeline = DevPipeline(assistant).debug_then_fix("ValueError")
    result = pipeline.run("x = 1/0")
    assert "debug" in result.outputs
    assert "refactor" in result.outputs
