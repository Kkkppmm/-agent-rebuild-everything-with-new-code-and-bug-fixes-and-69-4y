"""Observability callbacks for LLM clients."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any, Protocol

from devai.core.models import Message, Tool


class CallbackHandler(Protocol):
    """Protocol for LLM event callbacks."""

    def on_llm_start(self, messages: list[Message], **kwargs: Any) -> None: ...

    def on_llm_end(self, response: str) -> None: ...

    def on_llm_error(self, error: Exception) -> None: ...


class LoggingCallback:
    """Simple callback that records LLM call events."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def on_llm_start(self, messages: list[Message], **kwargs: Any) -> None:
        self.events.append(
            {
                "event": "start",
                "message_count": len(messages),
                "kwargs": kwargs,
            }
        )

    def on_llm_end(self, response: str) -> None:
        self.events.append({"event": "end", "response_length": len(response)})

    def on_llm_error(self, error: Exception) -> None:
        self.events.append({"event": "error", "error": str(error)})


class ObservedLLMClient:
    """LLM client wrapper that fires callbacks on each call."""

    def __init__(self, client: Any, callbacks: list[CallbackHandler] | None = None) -> None:
        self.client = client
        self.callbacks = callbacks or []

    def _fire_start(self, messages: list[Message], **kwargs: Any) -> None:
        for cb in self.callbacks:
            cb.on_llm_start(messages, **kwargs)

    def _fire_end(self, response: str) -> None:
        for cb in self.callbacks:
            cb.on_llm_end(response)

    def _fire_error(self, error: Exception) -> None:
        for cb in self.callbacks:
            cb.on_llm_error(error)

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self._fire_start(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        try:
            response = self.client.complete(
                messages,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            self._fire_end(response)
            return response
        except Exception as e:
            self._fire_error(e)
            raise

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        self._fire_start(messages, temperature=temperature, max_tokens=max_tokens)
        chunks: list[str] = []
        try:
            for chunk in self.client.stream(
                messages, temperature=temperature, max_tokens=max_tokens
            ):
                chunks.append(chunk)
                yield chunk
            self._fire_end("".join(chunks))
        except Exception as e:
            self._fire_error(e)
            raise

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self._fire_start(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        try:
            response = await self.client.acomplete(
                messages,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            self._fire_end(response)
            return response
        except Exception as e:
            self._fire_error(e)
            raise

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        self._fire_start(messages, temperature=temperature, max_tokens=max_tokens)
        chunks: list[str] = []
        try:
            async for chunk in self.client.astream(
                messages, temperature=temperature, max_tokens=max_tokens
            ):
                chunks.append(chunk)
                yield chunk
            self._fire_end("".join(chunks))
        except Exception as e:
            self._fire_error(e)
            raise
