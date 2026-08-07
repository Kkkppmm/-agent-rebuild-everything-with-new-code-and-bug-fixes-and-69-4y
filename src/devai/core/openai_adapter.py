"""Optional OpenAI SDK adapter for DevAI."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError
from devai.core.models import Message, Tool


class OpenAIAdapter:
    """LLM client backed by the official OpenAI Python SDK.

  Requires the optional ``openai`` package::

      pip install "devai[openai]"
    """

    def __init__(self, config: DevAIConfig | None = None, **kwargs: Any) -> None:
        try:
            from openai import AsyncOpenAI, OpenAI
        except ImportError as exc:
            raise ImportError(
                'OpenAI SDK not installed. Run: pip install "devai[openai]"'
            ) from exc

        if config is None:
            config = DevAIConfig(**kwargs)
        self.config = config
        client_kwargs: dict[str, Any] = {"api_key": config.api_key}
        if config.base_url:
            client_kwargs["base_url"] = config.base_url
        self._client = OpenAI(**client_kwargs)
        self._async_client = AsyncOpenAI(**client_kwargs)

    def _to_messages(self, messages: list[Message]) -> list[dict[str, str]]:
        return [{"role": m.role.value, "content": m.content} for m in messages]

    def _to_tools(self, tools: list[Tool] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        return [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                },
            }
            for tool in tools
        ]

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Complete a chat request using the OpenAI SDK."""
        try:
            response = self._client.chat.completions.create(
                model=self.config.model,
                messages=self._to_messages(messages),
                tools=self._to_tools(tools),
                temperature=temperature if temperature is not None else self.config.temperature,
                max_tokens=max_tokens or self.config.max_tokens,
                response_format={"type": "json_object"} if json_mode else None,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            raise LLMError(str(exc)) from exc

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        """Stream a chat completion using the OpenAI SDK."""
        try:
            stream = self._client.chat.completions.create(
                model=self.config.model,
                messages=self._to_messages(messages),
                temperature=temperature if temperature is not None else self.config.temperature,
                max_tokens=max_tokens or self.config.max_tokens,
                stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
        except Exception as exc:
            raise LLMError(str(exc)) from exc

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Async chat completion using the OpenAI SDK."""
        try:
            response = await self._async_client.chat.completions.create(
                model=self.config.model,
                messages=self._to_messages(messages),
                tools=self._to_tools(tools),
                temperature=temperature if temperature is not None else self.config.temperature,
                max_tokens=max_tokens or self.config.max_tokens,
                response_format={"type": "json_object"} if json_mode else None,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            raise LLMError(str(exc)) from exc

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        """Async streaming chat completion using the OpenAI SDK."""
        try:
            stream = await self._async_client.chat.completions.create(
                model=self.config.model,
                messages=self._to_messages(messages),
                temperature=temperature if temperature is not None else self.config.temperature,
                max_tokens=max_tokens or self.config.max_tokens,
                stream=True,
            )
            async for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
        except Exception as exc:
            raise LLMError(str(exc)) from exc
