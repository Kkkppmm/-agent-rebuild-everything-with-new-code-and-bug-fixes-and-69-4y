"""Tests for chains."""

from pydantic import BaseModel

from devai.chains import LLMChain, SequentialChain, StructuredChain
from devai.core.client import MockLLMClient


def test_llm_chain():
    client = MockLLMClient(responses=["Sorted output"])
    chain = LLMChain(client, "Process this: {input}")
    result = chain.run("raw data")
    assert result == "Sorted output"


def test_sequential_chain():
    client = MockLLMClient(responses=["step1", "step2"])
    chain1 = LLMChain(client, "First: {input}")
    chain2 = LLMChain(client, "Second: {input}")
    seq = SequentialChain([chain1, chain2])
    result = seq.run("data")
    assert result == "step2"


class CodeReview(BaseModel):
    score: int
    summary: str


def test_structured_chain():
    client = MockLLMClient(responses=['{"score": 9, "summary": "Great code"}'])
    chain = StructuredChain(client, "Review: {code}", CodeReview)
    result = chain.run(code="def f(): pass")
    assert result.score == 9
    assert result.summary == "Great code"
