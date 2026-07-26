"""LLM and embedding clients with retry and streaming support."""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import APIError, RetryExhaustedError
from devai.core.models import ChatResponse, Message, StreamChunk, Tool, ToolCall


class LLMClient:
    """OpenAI-compatible HTTP client for chat completions."""

    def __init__(self, config: DevAIConfig | None = None, **kwargs: Any):
        if config is None:
            config = DevAIConfig(**kwargs)
        self.config = config

    def chat(
        self,
        messages: list[Message | dict[str, Any]],
        *,
        tools: list[Tool | dict[str, Any]] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
        model: str | None = None,
    ) -> ChatResponse:
        """Send a chat completion request."""
        payload = self._build_payload(
            messages, tools=tools, json_mode=json_mode,
            temperature=temperature, max_tokens=max_tokens, model=model,
        )
        data = self._request("POST", "/chat/completions", payload)
        return self._parse_response(data)

    def stream(
        self,
        messages: list[Message | dict[str, Any]],
        *,
        tools: list[Tool | dict[str, Any]] | None = None,
        temperature: float | None = None,
        model: str | None = None,
    ) -> Iterator[StreamChunk]:
        """Stream a chat completion response."""
        payload = self._build_payload(
            messages, tools=tools, temperature=temperature, model=model, stream=True,
        )
        self.config.validate()
        url = f"{self.config.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            **self.config.extra_headers,
        }

        with httpx.Client(timeout=self.config.timeout) as client:
            with client.stream("POST", url, json=payload, headers=headers) as response:
                if response.status_code >= 400:
                    raise APIError(
                        f"Stream request failed: {response.status_code}",
                        status_code=response.status_code,
                    )
                for line in response.iter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    chunk_data = json.loads(data_str)
                    yield self._parse_stream_chunk(chunk_data)

    async def achat(
        self,
        messages: list[Message | dict[str, Any]],
        **kwargs: Any,
    ) -> ChatResponse:
        """Async chat completion."""
        payload = self._build_payload(messages, **kwargs)
        data = await self._arequest("POST", "/chat/completions", payload)
        return self._parse_response(data)

    def _build_payload(
        self,
        messages: list[Message | dict[str, Any]],
        *,
        tools: list[Tool | dict[str, Any]] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
        model: str | None = None,
        stream: bool = False,
    ) -> dict[str, Any]:
        msg_list = [m.to_dict() if isinstance(m, Message) else m for m in messages]
        payload: dict[str, Any] = {
            "model": model or self.config.model,
            "messages": msg_list,
            "temperature": temperature if temperature is not None else self.config.temperature,
        }
        if max_tokens or self.config.max_tokens:
            payload["max_tokens"] = max_tokens or self.config.max_tokens
        if tools:
            payload["tools"] = [
                t.to_dict() if isinstance(t, Tool) else t for t in tools
            ]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        if stream:
            payload["stream"] = True
        return payload

    def _request(self, method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.config.validate()
        url = f"{self.config.base_url.rstrip('/')}{path}"
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            **self.config.extra_headers,
        }
        last_error: Exception | None = None
        for attempt in range(self.config.max_retries):
            try:
                with httpx.Client(timeout=self.config.timeout) as client:
                    response = client.request(method, url, json=payload, headers=headers)
                if response.status_code >= 400:
                    raise APIError(
                        f"API error: {response.status_code} — {response.text}",
                        status_code=response.status_code,
                    )
                return response.json()
            except (httpx.HTTPError, APIError) as exc:
                last_error = exc
                if attempt < self.config.max_retries - 1:
                    time.sleep(2 ** attempt)
        raise RetryExhaustedError(
            f"Request failed after {self.config.max_retries} attempts: {last_error}"
        )

    async def _arequest(self, method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.config.validate()
        url = f"{self.config.base_url.rstrip('/')}{path}"
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            **self.config.extra_headers,
        }
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.request(method, url, json=payload, headers=headers)
        if response.status_code >= 400:
            raise APIError(
                f"API error: {response.status_code} — {response.text}",
                status_code=response.status_code,
            )
        return response.json()

    def _parse_response(self, data: dict[str, Any]) -> ChatResponse:
        choice = data["choices"][0]
        message = choice["message"]
        tool_calls = []
        if message.get("tool_calls"):
            tool_calls = [ToolCall.from_dict(tc) for tc in message["tool_calls"]]
        return ChatResponse(
            content=message.get("content") or "",
            role=message.get("role", "assistant"),
            tool_calls=tool_calls,
            finish_reason=choice.get("finish_reason"),
            usage=data.get("usage", {}),
            raw=data,
        )

    def _parse_stream_chunk(self, data: dict[str, Any]) -> StreamChunk:
        choice = data["choices"][0]
        delta = choice.get("delta", {})
        tool_calls = []
        if delta.get("tool_calls"):
            tool_calls = [ToolCall.from_dict(tc) for tc in delta["tool_calls"]]
        return StreamChunk(
            content=delta.get("content") or "",
            tool_calls=tool_calls,
            finish_reason=choice.get("finish_reason"),
        )


class MockLLMClient:
    """Deterministic mock client for testing without API calls."""

    def __init__(
        self,
        responses: list[str] | None = None,
        tool_responses: list[ChatResponse] | None = None,
    ):
        self.responses = responses or ["Mock response from DevAI."]
        self.tool_responses = tool_responses or []
        self._call_count = 0
        self.last_messages: list[dict[str, Any]] = []
        self.last_tools: list[dict[str, Any]] | None = None

    def chat(
        self,
        messages: list[Message | dict[str, Any]],
        *,
        tools: list[Tool | dict[str, Any]] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> ChatResponse:
        self.last_messages = [
            m.to_dict() if isinstance(m, Message) else m for m in messages
        ]
        self.last_tools = [
            t.to_dict() if isinstance(t, Tool) else t for t in tools
        ] if tools else None

        if self.tool_responses and self._call_count < len(self.tool_responses):
            response = self.tool_responses[self._call_count]
            self._call_count += 1
            return response

        idx = min(self._call_count, len(self.responses) - 1)
        content = self.responses[idx]
        self._call_count += 1

        if json_mode and not content.strip().startswith("{"):
            content = json.dumps({"result": content})

        return ChatResponse(content=content)

    def stream(
        self,
        messages: list[Message | dict[str, Any]],
        **kwargs: Any,
    ) -> Iterator[StreamChunk]:
        response = self.chat(messages, **kwargs)
        for word in response.content.split():
            yield StreamChunk(content=word + " ")

    async def achat(self, messages: list[Message | dict[str, Any]], **kwargs: Any) -> ChatResponse:
        return self.chat(messages, **kwargs)


class EmbeddingClient:
    """Client for generating text embeddings."""

    def __init__(self, config: DevAIConfig | None = None, **kwargs: Any):
        if config is None:
            config = DevAIConfig(**kwargs)
        self.config = config
        self._llm = LLMClient(config)

    def embed(self, texts: list[str], model: str | None = None) -> list[list[float]]:
        """Generate embeddings for a list of texts."""
        self.config.validate()
        payload = {
            "model": model or self.config.embedding_model,
            "input": texts,
        }
        data = self._llm._request("POST", "/embeddings", payload)
        return [item["embedding"] for item in data["data"]]

    def embed_one(self, text: str, model: str | None = None) -> list[float]:
        """Generate embedding for a single text."""
        return self.embed([text], model=model)[0]
