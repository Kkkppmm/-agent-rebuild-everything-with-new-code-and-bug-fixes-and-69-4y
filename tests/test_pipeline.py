"""Tests for DevPipeline."""

from devai.core.client import MockLLMClient
from devai.pipeline import DevPipeline, PipelineStep


def test_pipeline_review():
    client = MockLLMClient(responses=["Looks good."])
    pipeline = DevPipeline(client=client)
    result = pipeline.review("def foo(): pass")
    assert result == "Looks good."
    assert len(pipeline.results) == 1


def test_pipeline_run_all():
    client = MockLLMClient(responses=["Review OK.", "Secure."])
    pipeline = DevPipeline(client=client)
    outputs = pipeline.run_all("def foo(): pass")
    assert "review" in outputs
    assert "security" in outputs
    assert len(pipeline.results) == 2


def test_pipeline_summary():
    client = MockLLMClient(responses=["Done."])
    pipeline = DevPipeline(client=client)
    assert pipeline.summary() == "No pipeline steps executed."
    pipeline.explain("x = 1")
    summary = pipeline.summary()
    assert "EXPLAIN" in summary
