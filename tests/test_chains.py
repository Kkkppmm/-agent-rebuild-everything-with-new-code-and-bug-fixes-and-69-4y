"""Tests for chains module."""

import pytest
from pydantic import BaseModel

from devai.chains import ChainStep, SequentialChain, SimpleChain, StructuredChain
from devai.core.client import MockLLMClient
from devai.prompts.template import PromptTemplate


class TestSimpleChain:
    def test_run(self):
        client = MockLLMClient(responses=["Review complete"])
        chain = SimpleChain(
            client=client,
            prompt=PromptTemplate("Review {code}", ["code"]),
        )
        result = chain.run(code="x=1")
        assert result == "Review complete"

    @pytest.mark.asyncio
    async def test_arun(self):
        client = MockLLMClient(responses=["Async result"])
        chain = SimpleChain(
            client=client,
            prompt=PromptTemplate("Do {task}", ["task"]),
        )
        result = await chain.arun(task="test")
        assert result == "Async result"


class TestSequentialChain:
    def test_run(self):
        client = MockLLMClient(responses=["Step 1 output", "Step 2 output"])
        chain = SequentialChain(
            client=client,
            steps=[
                ChainStep("analyze", PromptTemplate("Analyze {code}", ["code"]), "analysis"),
                ChainStep("fix", PromptTemplate("Fix based on {analysis}", ["analysis"]), "fix"),
            ],
        )
        results = chain.run(code="buggy code")
        assert "analysis" in results
        assert "fix" in results


class TestStructuredChain:
    def test_parse_output(self):
        class Review(BaseModel):
            summary: str
            score: int

        client = MockLLMClient(responses=['{"summary": "good", "score": 8}'])
        chain = StructuredChain(
            client=client,
            output_model=Review,
            prompt_template="Review: {code}",
        )
        result = chain.run(code="def f(): pass")
        assert result.summary == "good"
        assert result.score == 8
