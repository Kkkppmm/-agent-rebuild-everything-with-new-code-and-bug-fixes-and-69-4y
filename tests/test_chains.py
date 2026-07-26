"""Tests for chains."""

from pydantic import BaseModel

from devai.chains import SequentialChain, SimpleChain, StructuredChain
from devai.core.client import MockLLMClient


class TestSimpleChain:
    def test_run(self):
        client = MockLLMClient(responses=["Answer"])
        chain = SimpleChain(client, system_prompt="Be helpful")
        result = chain.run("What is Python?")
        assert result == "Answer"


class TestSequentialChain:
    def test_sequential(self):
        client = MockLLMClient(responses=["step1", "step2"])
        chain1 = SimpleChain(client, system_prompt="First")
        chain2 = SimpleChain(client, system_prompt="Second")
        seq = SequentialChain([chain1, chain2])
        result = seq.run("input")
        assert result == "step2"


class TestStructuredChain:
    def test_structured_output(self):
        class Review(BaseModel):
            score: int
            summary: str

        client = MockLLMClient(
            responses=['{"score": 8, "summary": "Good code"}'],
        )
        chain = StructuredChain(client, output_model=Review)
        result = chain.run("Review this code")
        assert result.score == 8
        assert result.summary == "Good code"
