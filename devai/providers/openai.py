"""OpenAI-compatible HTTP provider (OpenAI, Azure, Ollama, vLLM, etc.)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.exceptions import ConfigurationError, ProviderError
from devai.providers.base import BaseProvider
from devai.types import ChatResponse, Usage


class OpenAIProvider(BaseProvider):
    """Provider for OpenAI-compatible REST APIs."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 60.0,
        headers: dict[str, str] | None = None,
    ):
        if not base_url:
            raise ConfigurationError("base_url is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._extra_headers = headers or {}

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", **self._extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(self, method: str, path: str, json_body: dict[str, Any] | None = None) -> dict:
        url = f"{self.base_url}/{path.lstrip('/')}"
        with httpx.Client(timeout=self.timeout) as client:
            response = client.request(method, url, headers=self._headers(), json=json_body)
        if response.status_code >= 400:
            raise ProviderError(
                f"Provider error: {response.status_code}",
                status_code=response.status_code,
                body=response.text,
            )
        return response.json()

    async def _request_async(
        self, method: str, path: str, json_body: dict[str, Any] | None = None
    ) -> dict:
        url = f"{self.base_url}/{path.lstrip('/')}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.request(method, url, headers=self._headers(), json=json_body)
        if response.status_code >= 400:
            raise ProviderError(
                f"Provider error: {response.status_code}",
                status_code=response.status_code,
                body=response.text,
            )
        return response.json()

    def _build_chat_body(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float,
        max_tokens: int | None,
        tools: list[dict[str, Any]] | None,
        stream: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": stream,
        }
        if max_tokens is not None:
            body["max_tokens"] = max_tokens
        if tools:
            body["tools"] = tools
        body.update(kwargs)
        return body

    def _parse_chat_response(self, data: dict[str, Any], model: str) -> ChatResponse:
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        usage_data = data.get("usage", {})
        usage = Usage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            completion_tokens=usage_data.get("completion_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0),
        )
        tool_calls = message.get("tool_calls") or []
        return ChatResponse(
            content=message.get("content") or "",
            model=data.get("model", model),
            usage=usage,
            tool_calls=tool_calls,
            raw=data,
        )

    def chat(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> ChatResponse:
        body = self._build_chat_body(messages, model, temperature, max_tokens, tools, **kwargs)
        data = self._request("POST", "chat/completions", body)
        return self._parse_chat_response(data, model)

    async def chat_async(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> ChatResponse:
        body = self._build_chat_body(messages, model, temperature, max_tokens, tools, **kwargs)
        data = await self._request_async("POST", "chat/completions", body)
        return self._parse_chat_response(data, model)

    def chat_stream(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        body = self._build_chat_body(
            messages, model, temperature, max_tokens, None, stream=True, **kwargs
        )
        url = f"{self.base_url}/chat/completions"
        with httpx.Client(timeout=self.timeout) as client:
            with client.stream(
                "POST", url, headers=self._headers(), json=body
            ) as response:
                if response.status_code >= 400:
                    raise ProviderError(
                        f"Provider error: {response.status_code}",
                        status_code=response.status_code,
                        body=response.read().decode(),
                    )
                for line in response.iter_lines():
                    token = _parse_sse_delta(line)
                    if token:
                        yield token

    async def chat_stream_async(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        body = self._build_chat_body(
            messages, model, temperature, max_tokens, None, stream=True, **kwargs
        )
        url = f"{self.base_url}/chat/completions"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream(
                "POST", url, headers=self._headers(), json=body
            ) as response:
                if response.status_code >= 400:
                    raise ProviderError(
                        f"Provider error: {response.status_code}",
                        status_code=response.status_code,
                        body=(await response.aread()).decode(),
                    )
                async for line in response.aiter_lines():
                    token = _parse_sse_delta(line)
                    if token:
                        yield token

    def embed(self, texts: list[str], model: str, **kwargs: Any) -> list[list[float]]:
        body = {"model": model, "input": texts, **kwargs}
        data = self._request("POST", "embeddings", body)
        items = sorted(data.get("data", []), key=lambda x: x.get("index", 0))
        return [item["embedding"] for item in items]

    async def embed_async(
        self, texts: list[str], model: str, **kwargs: Any
    ) -> list[list[float]]:
        body = {"model": model, "input": texts, **kwargs}
        data = await self._request_async("POST", "embeddings", body)
        items = sorted(data.get("data", []), key=lambda x: x.get("index", 0))
        return [item["embedding"] for item in items]


def _parse_sse_delta(line: str) -> str | None:
    if not line or not line.startswith("data: "):
        return None
    payload = line[6:].strip()
    if payload == "[DONE]":
        return None
    try:
        chunk = json.loads(payload)
        delta = chunk.get("choices", [{}])[0].get("delta", {})
        return delta.get("content") or None
    except json.JSONDecodeError:
        return None
