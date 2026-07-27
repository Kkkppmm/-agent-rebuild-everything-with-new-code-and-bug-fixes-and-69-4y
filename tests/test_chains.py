"""Tests for chains."""

from pydantic import BaseModel

from devai import MockLLMClient
from devai.chains import SequentialChain, SimpleChain, StructuredChain


def test_simple_chain():
    chain = SimpleChain(MockLLMClient(responses=["answer"]), "What is $topic?")
    result = chain.run(topic="Python")
    assert result == "answer"


def test_sequential_chain():
    client = MockLLMClient(responses=["step1 output", "final output"])
    chain = SequentialChain(client, [("You summarize.", "Summarize: {input}")])
    result = chain.run("some code here")
    assert isinstance(result, str)


def test_structured_chain():
    class Review(BaseModel):
        score: int
        summary: str

    client = MockLLMClient(responses=['{"score": 8, "summary": "Good code"}'])
    chain = StructuredChain(client, "Review this: $code", Review)
    result = chain.run(code="def f(): pass")
    assert result.score == 8
    assert result.summary == "Good code"
