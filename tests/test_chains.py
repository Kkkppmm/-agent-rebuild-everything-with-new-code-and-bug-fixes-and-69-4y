"""Tests for chains."""

from pydantic import BaseModel

from devai import DevAIConfig, MockLLMClient
from devai.chains import SequentialChain, SimpleChain, StructuredChain


def test_simple_chain():
    client = MockLLMClient(responses=["Hello Dev!"])
    chain = SimpleChain(client, DevAIConfig(), prompt="Greet {name}")
    assert chain.run(name="Dev") == "Hello Dev!"


def test_sequential_chain():
    client = MockLLMClient(responses=["step1", "step2"])
    steps = [
        SimpleChain(client, DevAIConfig(), prompt="First {input}"),
        SimpleChain(client, DevAIConfig(), prompt="Second {previous_output}"),
    ]
    chain = SequentialChain(steps)
    result = chain.run(input="data")
    assert result == "step2"


def test_structured_chain():
    class Review(BaseModel):
        score: int
        summary: str

    client = MockLLMClient(responses=['{"score": 8, "summary": "Good code."}'])
    chain = StructuredChain(
        client,
        DevAIConfig(),
        prompt="Review: {code}",
        output_model=Review,
    )
    result = chain.run(code="def foo(): pass")
    assert result.score == 8
    assert result.summary == "Good code."
