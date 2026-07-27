"""Tests for chains."""

from pydantic import BaseModel

from devai.chains.chain import Chain, SequentialChain, StructuredChain
from devai.core.client import MockLLMClient


def test_chain_run():
    client = MockLLMClient(responses=["Review complete."])
    chain = Chain(client, "Review this code: {code}")
    result = chain.run(code="def foo(): pass")
    assert "Review complete" in result


def test_chain_callable():
    client = MockLLMClient(responses=["ok"])
    chain = Chain(client, "Test {x}")
    assert chain(x="1") == "ok"


def test_sequential_chain():
    client = MockLLMClient(responses=["step1 output", "step2 output"])
    step1 = Chain(client, "Step 1: {input}", output_key="step1")
    step2 = Chain(client, "Step 2: {input}", output_key="step2")
    seq = SequentialChain([step1, step2])
    results = seq.run(input="data")
    assert "step1" in results
    assert "final" in results


class ReviewResult(BaseModel):
    score: int
    summary: str


def test_structured_chain():
    client = MockLLMClient(responses=['{"score": 8, "summary": "Good code"}'])
    chain = StructuredChain(client, "Review: {code}", ReviewResult)
    result = chain.run(code="def foo(): pass")
    assert result.score == 8
    assert result.summary == "Good code"
