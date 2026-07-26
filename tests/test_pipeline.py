"""Tests for DevPipeline."""

from devai.core.client import MockLLMClient
from devai.pipeline import DevPipeline, PipelineResult


def test_pipeline_review():
    client = MockLLMClient(responses=["Review complete."])
    pipeline = DevPipeline(client=client)
    result = pipeline.review("def foo(): pass")
    assert isinstance(result, PipelineResult)
    assert result.step == "review"
    assert result.response.content == "Review complete."


def test_pipeline_explain():
    client = MockLLMClient(responses=["This is a function."])
    pipeline = DevPipeline(client=client)
    result = pipeline.explain("def bar(): return 1")
    assert result.step == "explain"
    assert "function" in result.response.content.lower()


def test_pipeline_debug():
    client = MockLLMClient(responses=["Fix the index."])
    pipeline = DevPipeline(client=client)
    result = pipeline.debug("IndexError", code="items[99]")
    assert result.step == "debug"
    assert result.metadata["error"] == "IndexError"


def test_pipeline_full_review():
    client = MockLLMClient(responses=["ok", "secure", "tests"])
    pipeline = DevPipeline(client=client)
    results = pipeline.full_review("def x(): pass")
    assert len(results) == 3
    assert [r.step for r in results] == ["review", "security_review", "generate_tests"]


def test_pipeline_history():
    client = MockLLMClient(responses=["a", "b"])
    pipeline = DevPipeline(client=client)
    pipeline.review("code1")
    pipeline.explain("code2")
    assert len(pipeline.history) == 2
    pipeline.clear_history()
    assert len(pipeline.history) == 0


def test_pipeline_default_mock_client():
    pipeline = DevPipeline(config=__import__("devai").DevAIConfig(provider="mock"))
    result = pipeline.review("def foo(): pass")
    assert result.response.content
