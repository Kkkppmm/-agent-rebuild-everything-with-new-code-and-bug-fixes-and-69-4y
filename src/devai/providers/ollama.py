"""Ollama local model provider (OpenAI-compatible API)."""

from __future__ import annotations

from typing import AsyncIterator

from devai.config import DevAIConfig
from devai.providers.openai import OpenAIProvider
from devai.types import ChatResponse, EmbeddingResponse, Message, ToolDefinition


class OllamaProvider:
    """Thin wrapper around OpenAI-compatible Ollama API."""

    name = "ollama"

    def __init__(self, config: DevAIConfig):
        # Ollama does not require an API key
        ollama_config = DevAIConfig(
            provider="ollama",
            api_key=config.api_key or "ollama",
            base_url=config.base_url or "http://localhost:11434/v1",
            model=config.model,
            timeout=config.timeout,
            max_retries=config.max_retries,
            extra_headers=config.extra_headers,
        )
        self._delegate = OpenAIProvider(ollama_config)
        self.config = ollama_config

    async def chat(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
    ) -> ChatResponse:
        response = await self._delegate.chat(
            messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
        )
        response.provider = self.name
        return response

    async def stream(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
    ) -> AsyncIterator:
        async for chunk in self._delegate.stream(
            messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
        ):
            yield chunk

    async def embed(self, texts: list[str], *, model: str) -> EmbeddingResponse:
        response = await self._delegate.embed(texts, model=model)
        response.provider = self.name
        return response
