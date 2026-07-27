"""Tests for chains."""

from pydantic import BaseModel

from devai.chains import SequentialChain, SimpleChain, StructuredChain
from devai.core.client import MockLLMClient


def test_simple_chain():
  client = MockLLMClient()
  chain = SimpleChain(client, "Analyze: {code}")
  result = chain.run(code="x = 1")
  assert result


def test_sequential_chain():
  client = MockLLMClient()
  steps = [
    SimpleChain(client, "Step 1: {input}"),
    SimpleChain(client, "Step 2: {previous_output}"),
  ]
  chain = SequentialChain(steps)
  results = chain.run(input="test")
  assert len(results) == 2


class ReviewResult(BaseModel):
  score: int
  summary: str


def test_structured_chain():
  client = MockLLMClient(responses={"json": '{"score": 8, "summary": "Good code"}'})
  chain = StructuredChain(
    client,
    "Review: {code}",
    ReviewResult,
  )
  result = chain.run(code="def foo(): pass")
  assert isinstance(result, ReviewResult)
