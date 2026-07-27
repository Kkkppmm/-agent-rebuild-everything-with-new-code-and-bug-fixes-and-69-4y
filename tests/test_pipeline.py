"""Tests for DevPipeline."""

from devai.core.client import MockLLMClient
from devai.pipeline import DevPipeline, PipelineStep


def test_pipeline_create():
  pipeline = DevPipeline.create(client=MockLLMClient())
  assert pipeline.assistant is not None


def test_pipeline_run():
  pipeline = DevPipeline.create(
    client=MockLLMClient(),
    steps=[
      PipelineStep(name="review", action="review"),
      PipelineStep(name="explain", action="explain"),
    ],
  )
  results = pipeline.run("x = 1")
  assert len(results) == 2
  assert results[0].step == "review"


def test_review_pipeline():
  pipeline = DevPipeline.create(client=MockLLMClient())
  results = pipeline.review_pipeline("def foo(): pass")
  assert "review" in results
