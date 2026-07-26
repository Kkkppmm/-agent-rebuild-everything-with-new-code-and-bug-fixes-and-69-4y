"""Tests for chains."""

from pydantic import BaseModel
from devai.chains.chain import Chain
from devai.chains.sequential import SequentialChain
from devai.chains.structured import StructuredChain
from devai.core.client import MockLLMClient
from devai.prompts.template import PromptTemplate


def test_chain_run():
    client = MockLLMClient(responses=["Review: looks good"])
    chain = Chain(client, "Review this: {code}")
    result = chain.run(code="def f(): pass")
    assert "looks good" in result


def test_chain_with_system_prompt():
    client = MockLLMClient(responses=["ok"])
    chain = Chain(client, "{input}", system_prompt="Be helpful")
    chain.run(input="test")
    assert client.calls[0][0].role.value == "system"


def test_sequential_chain():
    client = MockLLMClient(responses=["step1 result", "step2 result"])
    chains = [
        Chain(client, PromptTemplate("First: {input}", name="first")),
        Chain(client, PromptTemplate("Second: {output}", name="second")),
    ]
    seq = SequentialChain(chains)
    results = seq.run(input="data")
    assert "first" in results
    assert "second" in results


def test_structured_chain():
    class Score(BaseModel):
        value: int
        reason: str

    client = MockLLMClient(responses=['{"value": 9, "reason": "excellent"}'])
    chain = StructuredChain(client, Score, "Rate: {item}")
    result = chain.run(item="code quality")
    assert result.value == 9
    assert result.reason == "excellent"
