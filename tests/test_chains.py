"""Tests for chains module."""

from pydantic import BaseModel

from devai.chains import SequentialChain, SimpleChain, StructuredChain
from devai.core.client import MockLLMClient


def test_simple_chain():
  client = MockLLMClient(default_response="chain result")
  chain = SimpleChain(client, system="Be helpful")
  result = chain.run("Do something")
  assert result == "chain result"


def test_sequential_chain():
  client = MockLLMClient(responses=["step1 output", "final output"])
  chain = SequentialChain(client, steps=["Analyze: {input}", "Summarize: {input}"])
  result = chain.run("initial data")
  assert result == "final output"


def test_structured_chain():
  class ReviewResult(BaseModel):
    score: int
    summary: str

  client = MockLLMClient(responses=['{"score": 8, "summary": "Good code"}'])
  chain = StructuredChain(client, model=ReviewResult)
  result = chain.run("Review this code")
  assert result.score == 8
  assert result.summary == "Good code"
