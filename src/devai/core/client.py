"""LLM client with streaming, retries, and tool-calling support."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError, RateLimitError
from devai.core.models import LLMResponse, Message, Tool, ToolCall


class LLMClient:
    """OpenAI-compatible LLM client with retries and streaming."""

    def __init__(self, config: DevAIConfig | None = None, **kwargs: Any) -> None:
        if config is None:
            config = DevAIConfig.from_env()
        self.config = config.with_overrides(**kwargs)
        self._client = httpx.Client(
            base_url=self.config.base_url,
            headers=self._headers(),
            timeout=self.config.timeout,
        )
        self._async_client: httpx.AsyncClient | None = None

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self.config.base_url,
                headers=self._headers(),
                timeout=self.config.timeout,
            )
        return self._async_client

    def _build_payload(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        stream: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": kwargs.get("model", self.config.model),
            "messages": [m.to_api_dict() for m in messages],
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "stream": stream,
        }
        if tools:
            payload["tools"] = [t.to_api_dict() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _parse_response(self, data: dict[str, Any]) -> LLMResponse:
        choice = data["choices"][0]
        message = choice["message"]
        tool_calls: list[ToolCall] = []
        for tc in message.get("tool_calls") or []:
            func = tc["function"]
            tool_calls.append(
                ToolCall(
                    id=tc["id"],
                    name=func["name"],
                    arguments=json.loads(func["arguments"]),
                )
            )
        return LLMResponse(
            content=message.get("content") or "",
            tool_calls=tool_calls,
            finish_reason=choice.get("finish_reason"),
            usage=data.get("usage", {}),
        )

    def _request_with_retry(self, payload: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self.config.max_retries):
            try:
                response = self._client.post("/chat/completions", json=payload)
                if response.status_code == 429:
                    raise RateLimitError("Rate limit exceeded")
                if response.status_code >= 400:
                    raise LLMError(
                        f"API error {response.status_code}: {response.text}"
                    )
                return response.json()
            except RateLimitError:
                last_error = RateLimitError("Rate limit exceeded")
                time.sleep(self.config.retry_delay * (2**attempt))
            except httpx.HTTPError as exc:
                last_error = LLMError(str(exc))
                time.sleep(self.config.retry_delay * (2**attempt))
        raise last_error or LLMError("Request failed after retries")

    async def _async_request_with_retry(self, payload: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        client = self._get_async_client()
        for attempt in range(self.config.max_retries):
            try:
                response = await client.post("/chat/completions", json=payload)
                if response.status_code == 429:
                    raise RateLimitError("Rate limit exceeded")
                if response.status_code >= 400:
                    raise LLMError(
                        f"API error {response.status_code}: {response.text}"
                    )
                return response.json()
            except RateLimitError:
                last_error = RateLimitError("Rate limit exceeded")
                await asyncio.sleep(self.config.retry_delay * (2**attempt))
            except httpx.HTTPError as exc:
                last_error = LLMError(str(exc))
                await asyncio.sleep(self.config.retry_delay * (2**attempt))
        raise last_error or LLMError("Request failed after retries")

    def chat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a chat completion request."""
        payload = self._build_payload(
            messages, tools=tools, json_mode=json_mode, **kwargs
        )
        data = self._request_with_retry(payload)
        return self._parse_response(data)

    async def achat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> LLMResponse:
        """Async chat completion request."""
        payload = self._build_payload(
            messages, tools=tools, json_mode=json_mode, **kwargs
        )
        data = await self._async_request_with_retry(payload)
        return self._parse_response(data)

    def stream(
        self,
        messages: list[Message],
        **kwargs: Any,
    ) -> Iterator[str]:
        """Stream chat completion tokens."""
        payload = self._build_payload(messages, stream=True, **kwargs)
        with self._client.stream("POST", "/chat/completions", json=payload) as resp:
            if resp.status_code >= 400:
                raise LLMError(f"API error {resp.status_code}")
            for line in resp.iter_lines():
                if not line.startswith("data: "):
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
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Async stream chat completion tokens."""
        payload = self._build_payload(messages, stream=True, **kwargs)
        client = self._get_async_client()
        async with client.stream("POST", "/chat/completions", json=payload) as resp:
            if resp.status_code >= 400:
                raise LLMError(f"API error {resp.status_code}")
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str.strip() == "[DONE]":
                    break
                chunk = json.loads(data_str)
                delta = chunk["choices"][0].get("delta", {})
                content = delta.get("content")
                if content:
                    yield content

    def close(self) -> None:
        self._client.close()
        if self._async_client:
            asyncio.get_event_loop().run_until_complete(self._async_client.aclose())

    def __enter__(self) -> LLMClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self._client.close()


class MockLLMClient:
    """Deterministic mock client for testing without API calls."""

    def __init__(
        self,
        responses: list[str] | None = None,
        tool_responses: list[list[ToolCall]] | None = None,
    ) -> None:
        self.responses = responses or ["Mock response"]
        self.tool_responses = tool_responses or []
        self._call_count = 0
        self.last_messages: list[Message] = []

    def chat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> LLMResponse:
        self.last_messages = messages
        idx = min(self._call_count, len(self.responses) - 1)
        self._call_count += 1
        tool_calls: list[ToolCall] = []
        if self.tool_responses and idx < len(self.tool_responses):
            tool_calls = self.tool_responses[idx]
        return LLMResponse(
            content=self.responses[idx],
            tool_calls=tool_calls,
            finish_reason="stop",
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        )

    async def achat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> LLMResponse:
        return self.chat(messages, tools=tools, json_mode=json_mode, **kwargs)

    def stream(self, messages: list[Message], **kwargs: Any) -> Iterator[str]:
        response = self.chat(messages, **kwargs)
        for word in response.content.split():
            yield word + " "

    async def astream(
        self, messages: list[Message], **kwargs: Any
    ) -> AsyncIterator[str]:
        for token in self.stream(messages, **kwargs):
            yield token

    @staticmethod
    def make_tool_call(name: str, arguments: dict[str, Any]) -> ToolCall:
        return ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name=name, arguments=arguments)
