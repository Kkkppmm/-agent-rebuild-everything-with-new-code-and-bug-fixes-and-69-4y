"""Unified DevAI client for chat, streaming, embeddings, and tool loops."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from typing import Any

from devai.config import DevAIConfig
from devai.providers import get_provider
from devai.tools import ToolRegistry
from devai.types import ChatResponse, EmbeddingResponse, Message, Role, StreamChunk, ToolDefinition


class DevAI:
    """High-level client that routes requests to configured AI providers.

    Example::

        from devai import DevAI, Message, Role

        ai = DevAI(provider="openai")
        response = await ai.chat([
            Message(role=Role.SYSTEM, content="You are a helpful coding assistant."),
            Message(role=Role.USER, content="Explain Python decorators briefly."),
        ])
        print(response.content)
    """

    def __init__(
        self,
        *,
        provider: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
        config: DevAIConfig | None = None,
    ):
        self.config = config or DevAIConfig.from_env(provider)
        if provider:
            self.config.provider = provider.lower()
        if api_key is not None:
            self.config.api_key = api_key
        if base_url is not None:
            self.config.base_url = base_url
        if model is not None:
            self.config.model = model
        if timeout is not None:
            self.config.timeout = timeout
        self._provider = get_provider(self.config.provider, self.config)

    @property
    def provider_name(self) -> str:
        return self._provider.name

    async def chat(
        self,
        messages: list[Message] | list[dict[str, Any]],
        *,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
    ) -> ChatResponse:
        """Send a chat completion request."""
        resolved_model = self.config.resolve_model(model)
        normalized = self._normalize_messages(messages)
        return await self._provider.chat(
            normalized,
            model=resolved_model,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
        )

    async def stream(
        self,
        messages: list[Message] | list[dict[str, Any]],
        *,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
    ) -> AsyncIterator[StreamChunk]:
        """Stream a chat completion token-by-token."""
        resolved_model = self.config.resolve_model(model)
        normalized = self._normalize_messages(messages)
        async for chunk in self._provider.stream(
            normalized,
            model=resolved_model,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
        ):
            yield chunk

    async def embed(
        self,
        texts: str | list[str],
        *,
        model: str | None = None,
    ) -> EmbeddingResponse:
        """Generate embeddings for one or more texts."""
        if isinstance(texts, str):
            texts = [texts]
        embed_model = model or self.config.model or "text-embedding-3-small"
        return await self._provider.embed(texts, model=embed_model)

    async def ask(
        self,
        prompt: str,
        *,
        system: str | None = None,
        model: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Convenience method: send a single user prompt and return text."""
        messages: list[Message] = []
        if system:
            messages.append(Message(role=Role.SYSTEM, content=system))
        messages.append(Message(role=Role.USER, content=prompt))
        response = await self.chat(messages, model=model, **kwargs)
        return response.content

    async def run_tools(
        self,
        messages: list[Message],
        registry: ToolRegistry,
        *,
        model: str | None = None,
        max_rounds: int = 5,
        temperature: float = 0.7,
    ) -> ChatResponse:
        """Run an agent loop: chat → execute tools → chat until done."""
        history = list(messages)
        tools = registry.definitions
        last_response: ChatResponse | None = None

        for _ in range(max_rounds):
            last_response = await self.chat(
                history,
                model=model,
                tools=tools,
                temperature=temperature,
            )
            if not last_response.tool_calls:
                return last_response

            assistant_msg = Message(
                role=Role.ASSISTANT,
                content=last_response.content,
                tool_calls=last_response.tool_calls,
            )
            history.append(assistant_msg)
            history.extend(registry.execute_all(last_response.tool_calls))

        if last_response is None:
            raise RuntimeError("Tool loop produced no response.")
        return last_response

    def chat_sync(self, *args: Any, **kwargs: Any) -> ChatResponse:
        return asyncio.run(self.chat(*args, **kwargs))

    def ask_sync(self, *args: Any, **kwargs: Any) -> str:
        return asyncio.run(self.ask(*args, **kwargs))

    def embed_sync(self, *args: Any, **kwargs: Any) -> EmbeddingResponse:
        return asyncio.run(self.embed(*args, **kwargs))

    def stream_sync(self, *args: Any, **kwargs: Any) -> Iterator[StreamChunk]:
        async def _collect() -> list[StreamChunk]:
            chunks = []
            async for chunk in self.stream(*args, **kwargs):
                chunks.append(chunk)
            return chunks

        return iter(asyncio.run(_collect()))

    @staticmethod
    def _normalize_messages(
        messages: list[Message] | list[dict[str, Any]],
    ) -> list[Message]:
        normalized: list[Message] = []
        for item in messages:
            if isinstance(item, Message):
                normalized.append(item)
            else:
                normalized.append(Message(**item))
        return normalized
