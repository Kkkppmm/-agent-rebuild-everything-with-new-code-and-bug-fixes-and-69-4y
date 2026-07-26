"""Tests for DevAI chains."""

from pydantic import BaseModel

from devai.chains import Chain, SequentialChain, StructuredChain
from devai.core.client import MockLLMClient


def test_chain_run():
    client = MockLLMClient(responses=["The answer is 42"])
    chain = Chain(client)
    result = chain.run("What is the meaning of life?")
    assert "42" in result


def test_sequential_chain():
    client = MockLLMClient(responses=["step1 output", "step2 output"])
    chain1 = Chain(client, system_prompt="Step 1")
    chain2 = Chain(client, system_prompt="Step 2")
    seq = SequentialChain([("first", chain1), ("second", chain2)])
    results = seq.run("input")
    assert "first" in results
    assert "second" in results


def test_structured_chain():
    class CodeReview(BaseModel):
        summary: str
        score: int

    client = MockLLMClient(responses=['{"summary": "Good code", "score": 9}'])
    chain = StructuredChain(client, CodeReview)
    result = chain.run("Review: def add(a,b): return a+b")
    assert result.summary == "Good code"
    assert result.score == 9
