"""Tests for chains."""

from pydantic import BaseModel

from devai.chains.chain import Chain, SequentialChain, StructuredChain
from devai.core.client import MockLLMClient


def test_chain_run():
    client = MockLLMClient(responses=["Generated output"])
    chain = Chain(client, "Write a {topic} function")
    result = chain.run(topic="sorting")
    assert "Generated output" in result


def test_sequential_chain():
    client = MockLLMClient(responses=["step1 output", "step2 output"])
    chains = [
        Chain(client, "First: {input}"),
        Chain(client, "Second: {previous_output}"),
    ]
    seq = SequentialChain(chains)
    result = seq.run(input="data")
    assert "step2" in result


def test_structured_chain():
    class ReviewResult(BaseModel):
        score: int
        summary: str

    client = MockLLMClient(responses=['{"score": 8, "summary": "Good code"}'])
    chain = StructuredChain(client, "Review: {code}", ReviewResult)
    result = chain.run(code="x=1")
    assert result.score == 8
    assert result.summary == "Good code"
