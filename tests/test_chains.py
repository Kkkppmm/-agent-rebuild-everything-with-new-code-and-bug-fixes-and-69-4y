"""Tests for chains module."""

from pydantic import BaseModel

from devai.chains import Chain, SequentialChain, StructuredChain
from devai.core.client import MockLLMClient


class TestChain:
    def test_run(self):
        client = MockLLMClient(responses=["result"])
        chain = Chain(client, lambda x: f"Process {x}")
        assert chain.run(x="data") == "result"

    def test_sequential(self):
        client = MockLLMClient(responses=["step1", "step2"])
        c1 = Chain(client, lambda: "first")
        c2 = Chain(client, lambda previous_output: f"got {previous_output}")
        seq = SequentialChain(c1, c2)
        assert seq.run() == "step2"


class TestStructuredChain:
    def test_parse_output(self):
        class Review(BaseModel):
            score: int
            summary: str

        client = MockLLMClient(
            responses=['{"score": 8, "summary": "Good code"}']
        )
        chain = StructuredChain(
            client,
            lambda code: f"Review: {code}",
            output_model=Review,
        )
        result = chain.run(code="def f(): pass")
        assert result.score == 8
        assert result.summary == "Good code"
