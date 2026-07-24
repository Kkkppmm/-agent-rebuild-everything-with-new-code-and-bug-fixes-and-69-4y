"""Tests for chains."""

from pydantic import BaseModel

from devai.chains.chain import Chain, SequentialChain, StructuredChain
from devai.core.client import MockLLMClient


class ReviewResult(BaseModel):
    summary: str
    score: int


class TestChain:
    def test_run(self):
        llm = MockLLMClient(responses=["Generated output"])
        chain = Chain(llm, "Process: {input}")
        result = chain.run(input="test data")
        assert result["output"] == "Generated output"
        assert result["input"] == "test data"


class TestSequentialChain:
    def test_sequential(self):
        llm = MockLLMClient(responses=["Step 1 done", "Step 2 done"])
        c1 = Chain(llm, "First: {topic}", output_key="step1")
        c2 = Chain(llm, "Second: {topic}", output_key="step2")
        seq = SequentialChain([c1, c2])
        result = seq.run(topic="testing")
        assert result["step1"] == "Step 1 done"
        assert result["step2"] == "Step 2 done"


class TestStructuredChain:
    def test_parse_model(self):
        llm = MockLLMClient(responses=['{"summary": "Good code", "score": 8}'])
        chain = StructuredChain(
            llm,
            "Review: {code}",
            ReviewResult,
        )
        result = chain.run(code="def foo(): pass")
        assert isinstance(result, ReviewResult)
        assert result.score == 8
