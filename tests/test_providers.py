"""Tests for OpenAI provider with mocked HTTP."""

import pytest

from devai.config import DevAIConfig
from devai.providers.openai import OpenAIProvider
from devai.types import Message, Role


@pytest.fixture
def openai_provider():
    config = DevAIConfig(
        provider="openai",
        api_key="test-key",
        base_url="https://api.openai.com/v1",
        model="gpt-4o-mini",
    )
    return OpenAIProvider(config)


@pytest.mark.asyncio
async def test_openai_chat(httpx_mock, openai_provider):
    httpx_mock.add_response(
        json={
            "id": "chat-1",
            "model": "gpt-4o-mini",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello!"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        }
    )
    response = await openai_provider.chat(
        [Message(role=Role.USER, content="Hi")],
        model="gpt-4o-mini",
    )
    assert response.content == "Hello!"
    assert response.usage.total_tokens == 7
    assert response.provider == "openai"


@pytest.mark.asyncio
async def test_openai_embed(httpx_mock, openai_provider):
    httpx_mock.add_response(
        json={
            "model": "text-embedding-3-small",
            "data": [{"embedding": [0.1, 0.2, 0.3], "index": 0}],
            "usage": {"prompt_tokens": 2, "total_tokens": 2},
        }
    )
    response = await openai_provider.embed(["hello"], model="text-embedding-3-small")
    assert len(response.embeddings[0]) == 3


@pytest.mark.asyncio
async def test_openai_provider_error(httpx_mock, openai_provider):
    httpx_mock.add_response(status_code=401, json={"error": {"message": "Invalid key"}})
    from devai.exceptions import ProviderError

    with pytest.raises(ProviderError) as exc:
        await openai_provider.chat([Message(role=Role.USER, content="x")], model="gpt-4o-mini")
    assert exc.value.status_code == 401
