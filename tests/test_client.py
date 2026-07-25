"""Tests for DevAI client."""

import pytest

from devai import DevAI
from devai.config import DevAIConfig


@pytest.fixture
def ai_client():
    return DevAI(
        provider="openai",
        api_key="test-key",
        model="gpt-4o-mini",
    )


@pytest.mark.asyncio
async def test_ask(httpx_mock, ai_client):
    httpx_mock.add_response(
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"role": "assistant", "content": "4"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
    )
    result = await ai_client.ask("What is 2+2?")
    assert result == "4"


@pytest.mark.asyncio
async def test_normalize_dict_messages(httpx_mock, ai_client):
    httpx_mock.add_response(
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {},
        }
    )
    response = await ai_client.chat([{"role": "user", "content": "go"}])
    assert response.content == "ok"


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("DEVAI_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    config = DevAIConfig.from_env()
    assert config.provider == "anthropic"
    assert config.api_key == "sk-test"
