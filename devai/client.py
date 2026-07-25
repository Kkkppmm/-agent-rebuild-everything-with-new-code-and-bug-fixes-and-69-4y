"""Main DevAI client."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from typing import Any

from devai.chat import ChatSession, Message, Role
from devai.exceptions import ConfigurationError
from devai.providers.base import BaseProvider
from devai.providers.mock import MockProvider
from devai.providers.openai import OpenAIProvider
from devai.tools import ToolRegistry
from devai.types import ChatResponse
from devai.utils.retry import retry_async, retry_sync


class DevAI:
    """
    Developer-friendly AI client.

    Examples::

        # Quick one-liner with mock provider (no API key)
        ai = DevAI.mock()
        print(ai.chat("Hello!"))

        # OpenAI-compatible API
        ai = DevAI(api_key="sk-...", model="gpt-4o-mini")
        print(ai.chat("Explain recursion"))

        # Stateful session
        session = ai.session(system="You are a helpful coding assistant.")
        session.complete(ai, "How do I read a file in Python?")
    """

    def __init__(
        self,
        provider: BaseProvider | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str = "gpt-4o-mini",
        embedding_model: str = "text-embedding-3-small",
        max_retries: int = 3,
        tools: ToolRegistry | None = None,
    ):
        if provider is not None:
            self.provider = provider
        elif api_key is not None or base_url is not None:
            key = api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("DEVAI_API_KEY")
            url = base_url or os.environ.get("DEVAI_BASE_URL") or "https://api.openai.com/v1"
            self.provider = OpenAIProvider(api_key=key, base_url=url)
        else:
            env_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("DEVAI_API_KEY")
            if env_key:
                url = os.environ.get("DEVAI_BASE_URL") or "https://api.openai.com/v1"
                self.provider = OpenAIProvider(api_key=env_key, base_url=url)
            else:
                self.provider = MockProvider()

        self.model = model
        self.embedding_model = embedding_model
        self.max_retries = max_retries
        self.tools = tools or ToolRegistry()

    @classmethod
    def mock(cls, response: str = "Mock response from DevAI.") -> DevAI:
        """Create a client with the mock provider (no API key required)."""
        return cls(provider=MockProvider(default_response=response))

    @classmethod
    def openai(
        cls,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
    ) -> DevAI:
        """Create a client for OpenAI or compatible endpoints."""
        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ConfigurationError(
                "API key required. Pass api_key or set OPENAI_API_KEY."
            )
        return cls(provider=OpenAIProvider(api_key=key, base_url=base_url), model=model)

    @classmethod
    def ollama(cls, model: str = "llama3.2", base_url: str = "http://localhost:11434/v1") -> DevAI:
        """Create a client for local Ollama instances."""
        return cls(provider=OpenAIProvider(api_key="ollama", base_url=base_url), model=model)

    def session(
        self,
        system: str | None = None,
        max_history: int | None = None,
    ) -> ChatSession:
        """Start a new conversation session."""
        return ChatSession(system=system, max_history=max_history)

    def chat(
        self,
        message: str | Message | list[Message | dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        system: str | None = None,
        use_tools: bool = False,
        **kwargs: Any,
    ) -> ChatResponse:
        """Send a chat message and return the response."""
        messages = self._normalize_messages(message, system)
        return self.chat_messages(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            use_tools=use_tools,
            **kwargs,
        )

    def chat_messages(
        self,
        messages: list[dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        use_tools: bool = False,
        **kwargs: Any,
    ) -> ChatResponse:
        """Send a pre-built message list to the provider."""
        tool_schema = tools
        if tool_schema is None and use_tools and self.tools:
            tool_schema = self.tools.to_openai_schema()
        return retry_sync(
            self.provider.chat,
            messages,
            model or self.model,
            temperature,
            max_tokens,
            tool_schema,
            max_retries=self.max_retries,
            **kwargs,
        )

    async def chat_async(
        self,
        message: str | Message | list[Message | dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        system: str | None = None,
        use_tools: bool = False,
        **kwargs: Any,
    ) -> ChatResponse:
        messages = self._normalize_messages(message, system)
        return await self.chat_messages_async(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            use_tools=use_tools,
            **kwargs,
        )

    async def chat_messages_async(
        self,
        messages: list[dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        use_tools: bool = False,
        **kwargs: Any,
    ) -> ChatResponse:
        tool_schema = tools
        if tool_schema is None and use_tools and self.tools:
            tool_schema = self.tools.to_openai_schema()
        return await retry_async(
            self.provider.chat_async,
            messages,
            model or self.model,
            temperature,
            max_tokens,
            tool_schema,
            max_retries=self.max_retries,
            **kwargs,
        )

    def chat_stream(
        self,
        message: str | Message | list[Message | dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        system: str | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        messages = self._normalize_messages(message, system)
        return self.chat_messages_stream(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

    def chat_messages_stream(
        self,
        messages: list[dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        return self.provider.chat_stream(
            messages, model or self.model, temperature, max_tokens, **kwargs
        )

    def chat_stream_async(
        self,
        message: str | Message | list[Message | dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        system: str | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        messages = self._normalize_messages(message, system)
        return self.chat_messages_stream_async(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

    def chat_messages_stream_async(
        self,
        messages: list[dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        return self.provider.chat_stream_async(
            messages, model or self.model, temperature, max_tokens, **kwargs
        )

    def embed(self, texts: list[str] | str, model: str | None = None, **kwargs: Any) -> list[list[float]]:
        """Generate embeddings for one or more texts."""
        if isinstance(texts, str):
            texts = [texts]
        return retry_sync(
            self.provider.embed,
            texts,
            model or self.embedding_model,
            max_retries=self.max_retries,
            **kwargs,
        )

    async def embed_async(
        self, texts: list[str] | str, model: str | None = None, **kwargs: Any
    ) -> list[list[float]]:
        if isinstance(texts, str):
            texts = [texts]
        return await retry_async(
            self.provider.embed_async,
            texts,
            model or self.embedding_model,
            max_retries=self.max_retries,
            **kwargs,
        )

    def run_with_tools(
        self,
        message: str,
        model: str | None = None,
        max_rounds: int = 5,
        **kwargs: Any,
    ) -> ChatResponse:
        """Chat loop that executes tool calls until the model returns text."""
        session = self.session()
        session.add_user(message)
        tools_schema = self.tools.to_openai_schema()

        for _ in range(max_rounds):
            response = self.chat_messages(
                messages=session.to_messages(),
                model=model,
                temperature=kwargs.get("temperature", 0.7),
                max_tokens=kwargs.get("max_tokens"),
                tools=tools_schema if self.tools else None,
            )
            if not response.tool_calls:
                session.add_assistant(response.content)
                return response

            session.add_assistant(response.content, tool_calls=response.tool_calls)
            for call in response.tool_calls:
                fn = call.get("function", {})
                name = fn.get("name", "")
                import json

                args = json.loads(fn.get("arguments", "{}"))
                result = self.tools.execute(name, args)
                session.add_tool_result(call.get("id", name), str(result))

        return response

    def _normalize_messages(
        self,
        message: str | Message | list[Message | dict[str, Any]],
        system: str | None = None,
    ) -> list[dict[str, Any]]:
        messages: list[dict[str, Any]] = []
        if system:
            messages.append({"role": "system", "content": system})

        if isinstance(message, str):
            messages.append({"role": "user", "content": message})
        elif isinstance(message, Message):
            messages.append(message.to_dict())
        else:
            for item in message:
                if isinstance(item, Message):
                    messages.append(item.to_dict())
                else:
                    messages.append(item)
        return messages
