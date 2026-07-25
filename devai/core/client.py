"""OpenAI-compatible async/sync LLM client."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator, Iterator

import httpx

from devai.core.config import DevAIConfig
from devai.core.models import Message, ToolCall, ToolDefinition


class LLMClient:
    """HTTP client for OpenAI-compatible chat completion APIs."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig()

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        headers.update(self.config.extra_headers)
        return headers

    def _build_payload(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": kwargs.get("model", self.config.model),
            "messages": [m.to_api() for m in messages],
            "temperature": kwargs.get("temperature", self.config.temperature),
            "stream": stream,
        }
        max_tokens = kwargs.get("max_tokens", self.config.max_tokens)
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if tools:
            payload["tools"] = [t.to_api() for t in tools]
        return payload

    def _parse_response(self, data: dict[str, Any]) -> Message:
        choice = data["choices"][0]
        message = choice["message"]
        tool_calls = None
        if message.get("tool_calls"):
            tool_calls = [ToolCall.from_api(tc) for tc in message["tool_calls"]]
        return Message.assistant(content=message.get("content"), tool_calls=tool_calls)

    def chat(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        **kwargs: Any,
    ) -> Message:
        """Send a synchronous chat completion request."""
        payload = self._build_payload(messages, tools=tools, stream=False, **kwargs)
        with httpx.Client(timeout=self.config.timeout) as client:
            response = client.post(
                f"{self.config.base_url.rstrip('/')}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            response.raise_for_status()
            return self._parse_response(response.json())

    async def achat(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        **kwargs: Any,
    ) -> Message:
        """Send an async chat completion request."""
        payload = self._build_payload(messages, tools=tools, stream=False, **kwargs)
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(
                f"{self.config.base_url.rstrip('/')}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            response.raise_for_status()
            return self._parse_response(response.json())

    def stream(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        """Stream text deltas from a chat completion."""
        payload = self._build_payload(messages, tools=tools, stream=True, **kwargs)
        with httpx.Client(timeout=self.config.timeout) as client:
            with client.stream(
                "POST",
                f"{self.config.base_url.rstrip('/')}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0].get("delta", {})
                    content = delta.get("content")
                    if content:
                        yield content

    async def astream(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Async stream text deltas from a chat completion."""
        payload = self._build_payload(messages, tools=tools, stream=True, **kwargs)
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.config.base_url.rstrip('/')}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0].get("delta", {})
                    content = delta.get("content")
                    if content:
                        yield content
