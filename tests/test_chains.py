"""Tests for DevAI chains."""

import pytest
from pydantic import BaseModel

from devai.chains import SequentialChain, SimpleChain, StructuredChain
from devai.core import MockLLMClient
from devai.prompts import CODE_REVIEW, EXPLAIN


class TestSimpleChain:
    def test_run(self):
        client = MockLLMClient(default_response="Looks good")
        chain = SimpleChain(client, CODE_REVIEW)
        result = chain.run(code="def foo(): pass")
        assert result == "Looks good"


class TestSequentialChain:
    def test_multiple_steps(self):
        client = MockLLMClient(responses=["Review done", "Explanation done"])
        chain = SequentialChain(client)
        chain.add_step(CODE_REVIEW, "review").add_step(EXPLAIN, "explanation")
        results = chain.run(code="x = 1")
        assert "review" in results
        assert "explanation" in results


class TestStructuredChain:
    def test_parse_output(self):
        class ReviewResult(BaseModel):
            score: int
            summary: str

        client = MockLLMClient(
            default_response='{"score": 8, "summary": "Good code"}'
        )
        chain = StructuredChain(client, CODE_REVIEW, ReviewResult)
        result = chain.run(code="def foo(): pass")
        assert result.score == 8
        assert result.summary == "Good code"

    @pytest.mark.asyncio
    async def test_arun(self):
        class Result(BaseModel):
            value: str

        client = MockLLMClient(default_response='{"value": "test"}')
        chain = StructuredChain(client, EXPLAIN, Result)
        result = await chain.arun(code="x=1")
        assert result.value == "test"
