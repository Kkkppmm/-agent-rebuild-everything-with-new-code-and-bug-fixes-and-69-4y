"""Tests for DevAI chains."""

from pydantic import BaseModel

from devai.chains import SimpleChain, SequentialChain, StructuredChain
from devai.core.client import MockLLMClient
from devai.prompts import PromptTemplate


class TestSimpleChain:
    def test_run(self):
        client = MockLLMClient(responses=["Review: looks good"])
        chain = SimpleChain(client, "Review this code: {code}")
        result = chain.run(code="def foo(): pass")
        assert "looks good" in result


class TestSequentialChain:
    def test_run(self):
        client = MockLLMClient(responses=["Step 1 done", "Step 2 done"])
        step1 = SimpleChain(client, "First: {input}")
        step2 = SimpleChain(client, "Second: {previous_output}")
        chain = SequentialChain([step1, step2])
        results = chain.run(input="test")
        assert len(results) == 2
        assert "Step 1" in results[0]
        assert "Step 2" in results[1]


class TestStructuredChain:
    def test_run(self):
        class ReviewResult(BaseModel):
            rating: str
            summary: str

        client = MockLLMClient(
            responses=['{"rating": "PASS", "summary": "Code is clean"}']
        )
        chain = StructuredChain(
            client,
            "Review: {code}",
            output_model=ReviewResult,
        )
        result = chain.run(code="def foo(): pass")
        assert result.rating == "PASS"
        assert result.summary == "Code is clean"
