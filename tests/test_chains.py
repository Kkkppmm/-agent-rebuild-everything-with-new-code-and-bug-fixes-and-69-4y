"""Tests for DevAI chains."""

from unittest.mock import AsyncMock

import pytest

from devai.chains.chain import Chain, SequentialChain
from devai.core.config import DevAIConfig
from devai.core.models import CompletionResponse
from devai.prompts.template import PromptTemplate


class TestChain:
    @pytest.fixture
    def config(self):
        return DevAIConfig(api_key="test-key")

    @pytest.mark.asyncio
    async def test_run(self, config):
        chain = Chain("Review this {language} code: {code}", config=config)
        chain.client.chat = AsyncMock(
            return_value=CompletionResponse(content="LGTM", finish_reason="stop")
        )
        result = await chain.run(code="x=1", language="python")
        assert result == "LGTM"

    @pytest.mark.asyncio
    async def test_run_with_system_prompt(self, config):
        chain = Chain("Hello {name}", config=config, system_prompt="Be brief.")
        chain.client.chat = AsyncMock(
            return_value=CompletionResponse(content="Hi!", finish_reason="stop")
        )
        result = await chain.run(name="Alice")
        assert result == "Hi!"
        call_args = chain.client.chat.call_args[0][0]
        assert call_args[0].role.value == "system"

    def test_run_sync(self, config):
        chain = Chain("Say {word}", config=config)
        chain.client.chat = AsyncMock(
            return_value=CompletionResponse(content="hello", finish_reason="stop")
        )
        result = chain.run_sync(word="hello")
        assert result == "hello"


class TestSequentialChain:
    @pytest.fixture
    def config(self):
        return DevAIConfig(api_key="test-key")

    @pytest.mark.asyncio
    async def test_sequential(self, config):
        chain1 = Chain("Step 1: analyze {input}", config=config)
        chain2 = Chain("Step 2: improve {output}", config=config)
        chain1.client.chat = AsyncMock(
            return_value=CompletionResponse(content="analysis done", finish_reason="stop")
        )
        chain2.client.chat = AsyncMock(
            return_value=CompletionResponse(content="improved code", finish_reason="stop")
        )
        seq = SequentialChain([chain1, chain2])
        results = await seq.run(input="my code")
        assert results["step_0"] == "analysis done"
        assert results["final"] == "improved code"
