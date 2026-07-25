"""Mock LLM client for testing without API calls."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

from devai.core.models import CompletionResponse, Message, StreamChunk, Tool, ToolCall


class MockLLMClient:
    """In-memory LLM client for unit tests and local development.

    Queue responses with :meth:`add_response` or pass them to the constructor.
    Each call to :meth:`chat` consumes the next queued response. When the queue
    is empty, the default response is returned.
    """

    def __init__(
        self,
        responses: list[str | CompletionResponse] | None = None,
        default: str | CompletionResponse = "Mock response",
    ):
        self._responses: list[CompletionResponse] = [
            self._to_response(r) for r in (responses or [])
        ]
        self._default = self._to_response(default)
        self.calls: list[dict[str, Any]] = []

    @staticmethod
    def _to_response(value: str | CompletionResponse) -> CompletionResponse:
        if isinstance(value, CompletionResponse):
            return value
        return CompletionResponse(content=value)

    def add_response(self, response: str | CompletionResponse) -> None:
        """Append a response to the queue."""
        self._responses.append(self._to_response(response))

    def _next_response(self) -> CompletionResponse:
        if self._responses:
            return self._responses.pop(0)
        return self._default

    async def chat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool | None = None,
        model: str | None = None,
    ) -> CompletionResponse:
        self.calls.append(
            {
                "messages": messages,
                "tools": tools,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "json_mode": json_mode,
                "model": model,
            }
        )
        return self._next_response()

    def chat_sync(self, messages: list[Message], **kwargs: Any) -> CompletionResponse:
        import asyncio

        return asyncio.run(self.chat(messages, **kwargs))

    async def stream(
        self,
        messages: list[Message],
        **kwargs: Any,
    ) -> AsyncIterator[StreamChunk]:
        response = await self.chat(messages, **kwargs)
        text = response.content
        if not text:
            yield StreamChunk(content="", finish_reason=response.finish_reason or "stop")
            return
        for word in text.split(" "):
            yield StreamChunk(content=word + " ")
        yield StreamChunk(content="", finish_reason=response.finish_reason or "stop")

    def stream_sync(self, messages: list[Message], **kwargs: Any) -> list[StreamChunk]:
        import asyncio

        async def _collect() -> list[StreamChunk]:
            chunks: list[StreamChunk] = []
            async for chunk in self.stream(messages, **kwargs):
                chunks.append(chunk)
            return chunks

        return asyncio.run(_collect())

    async def close(self) -> None:
        return None

    @classmethod
    def with_tool_loop(
        cls,
        tool_name: str,
        tool_args: dict[str, Any],
        final: str = "Task complete.",
    ) -> MockLLMClient:
        """Create a mock that requests a tool call, then returns a final answer."""
        return cls(
            responses=[
                CompletionResponse(
                    content="",
                    tool_calls=[
                        ToolCall(id="mock_call_1", name=tool_name, arguments=tool_args)
                    ],
                    finish_reason="tool_calls",
                ),
                CompletionResponse(content=final),
            ]
        )

    @classmethod
    def from_handler(
        cls,
        handler: Callable[[list[Message]], str | CompletionResponse],
    ) -> MockLLMClient:
        """Create a mock that computes responses from message history."""
        client = cls(default="")
        client._handler = handler  # type: ignore[attr-defined]
        return client
