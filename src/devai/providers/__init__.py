"""Provider protocol and registry."""

from __future__ import annotations

from typing import AsyncIterator, Protocol

from devai.types import (
    ChatResponse,
    EmbeddingResponse,
    Message,
    StreamChunk,
    ToolDefinition,
)


class Provider(Protocol):
    name: str

    async def chat(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
    ) -> ChatResponse: ...

    async def stream(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
    ) -> AsyncIterator[StreamChunk]: ...

    async def embed(
        self,
        texts: list[str],
        *,
        model: str,
    ) -> EmbeddingResponse: ...


def get_provider(name: str, config) -> Provider:
    from devai.providers.anthropic import AnthropicProvider
    from devai.providers.ollama import OllamaProvider
    from devai.providers.openai import OpenAIProvider

    providers = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "ollama": OllamaProvider,
    }
    cls = providers.get(name.lower())
    if cls is None:
        raise ValueError(f"Unknown provider '{name}'. Choose from: {', '.join(providers)}")
    return cls(config)
