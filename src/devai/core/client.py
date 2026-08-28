"""LLM client implementations for DevAI."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any, Protocol

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError
from devai.core.models import Message, Tool
from devai.core.retries import async_with_retries, with_retries


class LLMClientProtocol(Protocol):
    """Protocol for LLM clients."""

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str: ...

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]: ...

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str: ...

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]: ...


class LLMClient:
    """OpenAI-compatible LLM client with sync/async and streaming support."""

    def __init__(self, config: DevAIConfig | None = None, **kwargs: Any) -> None:
        if config is None:
            config = DevAIConfig(**kwargs)
        self.config = config
        self._sync_client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        headers.update(self.config.extra_headers)
        return headers

    def _build_payload(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream: bool = False,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.config.max_tokens,
        }
        if stream:
            payload["stream"] = True
        if tools:
            payload["tools"] = [t.to_dict() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _extract_content(self, data: dict[str, Any]) -> str:
        choices = data.get("choices", [])
        if not choices:
            raise LLMError("No choices in LLM response")
        message = choices[0].get("message", {})
        content = message.get("content", "")
        tool_calls = message.get("tool_calls")
        if tool_calls and not content:
            return json.dumps({"tool_calls": tool_calls})
        return content or ""

    def _extract_tool_calls(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        choices = data.get("choices", [])
        if not choices:
            return []
        return choices[0].get("message", {}).get("tool_calls", [])

    @property
    def sync_client(self) -> httpx.Client:
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                base_url=self.config.base_url,
                headers=self._headers(),
                timeout=self.config.timeout,
            )
        return self._sync_client

    @property
    def async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self.config.base_url,
                headers=self._headers(),
                timeout=self.config.timeout,
            )
        return self._async_client

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self.config.validate()
        payload = self._build_payload(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        def _call() -> str:
            resp = self.sync_client.post("/chat/completions", json=payload)
            if resp.status_code != 200:
                raise LLMError(f"LLM API error {resp.status_code}: {resp.text}")
            return self._extract_content(resp.json())

        return with_retries(
            _call,
            max_retries=self.config.max_retries,
            delay=self.config.retry_delay,
            exceptions=(LLMError, httpx.HTTPError),
        )

    def complete_with_tools(
        self,
        messages: list[Message],
        tools: list[Tool],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> tuple[str, list[dict[str, Any]]]:
        """Complete and return both content and tool calls."""
        self.config.validate()
        payload = self._build_payload(
            messages, tools=tools, temperature=temperature, max_tokens=max_tokens
        )

        def _call() -> tuple[str, list[dict[str, Any]]]:
            resp = self.sync_client.post("/chat/completions", json=payload)
            if resp.status_code != 200:
                raise LLMError(f"LLM API error {resp.status_code}: {resp.text}")
            data = resp.json()
            return self._extract_content(data), self._extract_tool_calls(data)

        return with_retries(
            _call,
            max_retries=self.config.max_retries,
            delay=self.config.retry_delay,
            exceptions=(LLMError, httpx.HTTPError),
        )

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        self.config.validate()
        payload = self._build_payload(
            messages, temperature=temperature, max_tokens=max_tokens, stream=True
        )
        with self.sync_client.stream("POST", "/chat/completions", json=payload) as resp:
            if resp.status_code != 200:
                raise LLMError(f"LLM API error {resp.status_code}: {resp.text}")
            for line in resp.iter_lines():
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0].get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        yield content
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self.config.validate()
        payload = self._build_payload(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        async def _call() -> str:
            resp = await self.async_client.post("/chat/completions", json=payload)
            if resp.status_code != 200:
                raise LLMError(f"LLM API error {resp.status_code}: {resp.text}")
            return self._extract_content(resp.json())

        return await async_with_retries(
            _call,
            max_retries=self.config.max_retries,
            delay=self.config.retry_delay,
            exceptions=(LLMError, httpx.HTTPError),
        )

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        self.config.validate()
        payload = self._build_payload(
            messages, temperature=temperature, max_tokens=max_tokens, stream=True
        )
        async with self.async_client.stream("POST", "/chat/completions", json=payload) as resp:
            if resp.status_code != 200:
                raise LLMError(f"LLM API error {resp.status_code}: {resp.text}")
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0].get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        yield content
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue

    def close(self) -> None:
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None

    async def aclose(self) -> None:
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None


class MockLLMClient:
    """Mock LLM client for testing without an API key."""

    def __init__(
        self,
        default_response: str = "Mock response from DevAI.",
        responses: list[str] | None = None,
    ) -> None:
        self.default_response = default_response
        self.responses = list(responses) if responses else []
        self.call_history: list[list[Message]] = []

    def _next_response(self) -> str:
        if self.responses:
            return self.responses.pop(0)
        return self.default_response

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self.call_history.append(messages)
        return self._next_response()

    def complete_with_tools(
        self,
        messages: list[Message],
        tools: list[Tool],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> tuple[str, list[dict[str, Any]]]:
        self.call_history.append(messages)
        response = self._next_response()
        try:
            data = json.loads(response)
            if "tool_calls" in data:
                return "", data["tool_calls"]
        except (json.JSONDecodeError, TypeError):
            pass
        return response, []

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        self.call_history.append(messages)
        response = self._next_response()
        for word in response.split():
            yield word + " "

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        return self.complete(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        for chunk in self.stream(messages, temperature=temperature, max_tokens=max_tokens):
            yield chunk


class CachedLLMClient:
    """LLM client wrapper that caches responses by message hash."""

    def __init__(self, client: LLMClientProtocol) -> None:
        self.client = client
        self._cache: dict[str, str] = {}

    def _cache_key(self, messages: list[Message], **kwargs: Any) -> str:
        parts = [json.dumps(m.to_dict(), sort_keys=True) for m in messages]
        parts.append(json.dumps(kwargs, sort_keys=True, default=str))
        return "|".join(parts)

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        key = self._cache_key(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if key not in self._cache:
            self._cache[key] = self.client.complete(
                messages,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        return self._cache[key]

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        return self.client.stream(
            messages, temperature=temperature, max_tokens=max_tokens
        )

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        key = self._cache_key(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if key not in self._cache:
            self._cache[key] = await self.client.acomplete(
                messages,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        return self._cache[key]

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        async for chunk in self.client.astream(
            messages, temperature=temperature, max_tokens=max_tokens
        ):
            yield chunk

    def clear_cache(self) -> None:
        self._cache.clear()

    @property
    def cache_size(self) -> int:
        return len(self._cache)
