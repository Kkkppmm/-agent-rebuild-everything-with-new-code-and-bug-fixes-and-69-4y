"""OpenAI-compatible async/sync LLM client."""

from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator, Iterator, TypeVar

import httpx
from pydantic import BaseModel

from devai.core.config import DevAIConfig
from devai.core.exceptions import APIError
from devai.core.models import Message, ToolCall, ToolDefinition

T = TypeVar("T", bound=BaseModel)


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
        response_format = kwargs.get("response_format")
        if response_format is not None:
            payload["response_format"] = response_format
        return payload

    def _parse_response(self, data: dict[str, Any]) -> Message:
        choice = data["choices"][0]
        message = choice["message"]
        tool_calls = None
        if message.get("tool_calls"):
            tool_calls = [ToolCall.from_api(tc) for tc in message["tool_calls"]]
        return Message.assistant(content=message.get("content"), tool_calls=tool_calls)

    def _request_with_retry(
        self,
        client: httpx.Client,
        url: str,
        payload: dict[str, Any],
    ) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(self.config.max_retries):
            try:
                response = client.post(url, headers=self._headers(), json=payload)
                if response.status_code >= 500 and attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_backoff * (2 ** attempt))
                    continue
                if response.status_code >= 400:
                    raise APIError(
                        f"API error {response.status_code}: {response.text}",
                        status_code=response.status_code,
                    )
                return response
            except httpx.TransportError as exc:
                last_exc = exc
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_backoff * (2 ** attempt))
                    continue
                raise APIError(f"Transport error after {self.config.max_retries} retries: {exc}") from exc
        raise APIError(f"Request failed: {last_exc}")

    async def _arequest_with_retry(
        self,
        client: httpx.AsyncClient,
        url: str,
        payload: dict[str, Any],
    ) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(self.config.max_retries):
            try:
                response = await client.post(url, headers=self._headers(), json=payload)
                if response.status_code >= 500 and attempt < self.config.max_retries - 1:
                    await self._async_sleep(self.config.retry_backoff * (2 ** attempt))
                    continue
                if response.status_code >= 400:
                    raise APIError(
                        f"API error {response.status_code}: {response.text}",
                        status_code=response.status_code,
                    )
                return response
            except httpx.TransportError as exc:
                last_exc = exc
                if attempt < self.config.max_retries - 1:
                    await self._async_sleep(self.config.retry_backoff * (2 ** attempt))
                    continue
                raise APIError(f"Transport error after {self.config.max_retries} retries: {exc}") from exc
        raise APIError(f"Request failed: {last_exc}")

    async def _async_sleep(self, seconds: float) -> None:
        import asyncio

        await asyncio.sleep(seconds)

    def chat(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        **kwargs: Any,
    ) -> Message:
        """Send a synchronous chat completion request."""
        payload = self._build_payload(messages, tools=tools, stream=False, **kwargs)
        url = f"{self.config.base_url.rstrip('/')}/chat/completions"
        with httpx.Client(timeout=self.config.timeout) as client:
            response = self._request_with_retry(client, url, payload)
            return self._parse_response(response.json())

    async def achat(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        **kwargs: Any,
    ) -> Message:
        """Send an async chat completion request."""
        payload = self._build_payload(messages, tools=tools, stream=False, **kwargs)
        url = f"{self.config.base_url.rstrip('/')}/chat/completions"
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await self._arequest_with_retry(client, url, payload)
            return self._parse_response(response.json())

    def chat_structured(
        self,
        messages: list[Message],
        schema: type[T],
        **kwargs: Any,
    ) -> T:
        """Request a JSON response and parse it into a Pydantic model."""
        response = self.chat(
            messages,
            response_format={"type": "json_object"},
            **kwargs,
        )
        if not response.content:
            raise APIError("Empty response for structured output")
        return schema.model_validate_json(response.content)

    async def achat_structured(
        self,
        messages: list[Message],
        schema: type[T],
        **kwargs: Any,
    ) -> T:
        """Async version of chat_structured."""
        response = await self.achat(
            messages,
            response_format={"type": "json_object"},
            **kwargs,
        )
        if not response.content:
            raise APIError("Empty response for structured output")
        return schema.model_validate_json(response.content)

    def embed(self, texts: list[str], **kwargs: Any) -> list[list[float]]:
        """Generate embeddings for a list of texts."""
        payload = {
            "model": kwargs.get("model", self.config.embedding_model),
            "input": texts,
        }
        url = f"{self.config.base_url.rstrip('/')}/embeddings"
        with httpx.Client(timeout=self.config.timeout) as client:
            response = self._request_with_retry(client, url, payload)
            data = response.json()
            return [item["embedding"] for item in data["data"]]

    async def aembed(self, texts: list[str], **kwargs: Any) -> list[list[float]]:
        """Async version of embed."""
        payload = {
            "model": kwargs.get("model", self.config.embedding_model),
            "input": texts,
        }
        url = f"{self.config.base_url.rstrip('/')}/embeddings"
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await self._arequest_with_retry(client, url, payload)
            data = response.json()
            return [item["embedding"] for item in data["data"]]

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
                if response.status_code >= 400:
                    raise APIError(
                        f"API error {response.status_code}: {response.text}",
                        status_code=response.status_code,
                    )
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
                if response.status_code >= 400:
                    raise APIError(
                        f"API error {response.status_code}: {response.text}",
                        status_code=response.status_code,
                    )
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
