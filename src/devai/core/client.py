"""LLM and embedding clients."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import AuthenticationError, LLMError, RateLimitError
from devai.core.messages import Message, ToolCall, ToolDefinition
from devai.core.retries import with_retries


class LLMClient:
    """OpenAI-compatible LLM client with streaming, tools, and JSON mode."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.require_api_key()}",
            "Content-Type": "application/json",
        }

    def _build_payload(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.config.max_tokens,
        }
        if tools:
            payload["tools"] = [t.to_openai_schema() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 401:
            raise AuthenticationError("Invalid API key")
        if response.status_code == 429:
            raise RateLimitError("Rate limit exceeded")
        if response.status_code >= 400:
            raise LLMError(f"API error {response.status_code}: {response.text}")
        return response.json()

    def _parse_completion(self, data: dict[str, Any]) -> Message:
        choice = data["choices"][0]["message"]
        tool_calls = None
        if choice.get("tool_calls"):
            tool_calls = [
                ToolCall(
                    id=tc["id"],
                    name=tc["function"]["name"],
                    arguments=json.loads(tc["function"]["arguments"]),
                )
                for tc in choice["tool_calls"]
            ]
        return Message.assistant(choice.get("content") or "", tool_calls=tool_calls)

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Message:
        """Send a chat completion request and return the assistant message."""
        payload = self._build_payload(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        def _call() -> Message:
            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.post(
                    f"{self.config.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
                data = self._handle_response(response)
                return self._parse_completion(data)

        return with_retries(
            _call,
            max_retries=self.config.max_retries,
            delay=self.config.retry_delay,
        )

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        """Stream chat completion tokens."""
        payload = self._build_payload(messages, temperature=temperature, max_tokens=max_tokens)
        payload["stream"] = True

        with httpx.Client(timeout=self.config.timeout) as client:
            with client.stream(
                "POST",
                f"{self.config.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as response:
                if response.status_code >= 400:
                    raise LLMError(f"Stream error {response.status_code}")
                for line in response.iter_lines():
                    if not line.startswith("data: "):
                        continue
                    chunk = line[6:]
                    if chunk == "[DONE]":
                        break
                    data = json.loads(chunk)
                    delta = data["choices"][0].get("delta", {})
                    if content := delta.get("content"):
                        yield content

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Message:
        """Async chat completion."""
        payload = self._build_payload(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(
                f"{self.config.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            data = self._handle_response(response)
            return self._parse_completion(data)

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        """Async streaming chat completion."""
        payload = self._build_payload(messages, temperature=temperature, max_tokens=max_tokens)
        payload["stream"] = True

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.config.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as response:
                if response.status_code >= 400:
                    raise LLMError(f"Stream error {response.status_code}")
                async for line in response.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    chunk = line[6:]
                    if chunk == "[DONE]":
                        break
                    data = json.loads(chunk)
                    delta = data["choices"][0].get("delta", {})
                    if content := delta.get("content"):
                        yield content


class MockLLMClient(LLMClient):
    """Deterministic mock client for testing without API calls."""

    def __init__(
        self,
        responses: list[str] | None = None,
        config: DevAIConfig | None = None,
    ) -> None:
        super().__init__(config or DevAIConfig(api_key="mock-key"))
        self._responses = responses or ["Mock response from DevAI."]
        self._call_count = 0
        self.last_messages: list[Message] = []

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Message:
        self.last_messages = messages
        idx = min(self._call_count, len(self._responses) - 1)
        self._call_count += 1
        content = self._responses[idx]
        if json_mode and not content.strip().startswith("{"):
            content = json.dumps({"result": content})
        return Message.assistant(content)

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        response = self.complete(messages, temperature=temperature, max_tokens=max_tokens)
        for word in response.content.split():
            yield word + " "

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Message:
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
        for token in self.stream(messages, temperature=temperature, max_tokens=max_tokens):
            yield token


class EmbeddingClient:
    """Client for generating text embeddings."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig()

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a list of texts."""
        with httpx.Client(timeout=self.config.timeout) as client:
            response = client.post(
                f"{self.config.base_url}/embeddings",
                headers={
                    "Authorization": f"Bearer {self.config.require_api_key()}",
                    "Content-Type": "application/json",
                },
                json={"model": self.config.embedding_model, "input": texts},
            )
            if response.status_code >= 400:
                raise LLMError(f"Embedding error {response.status_code}: {response.text}")
            data = response.json()
            return [item["embedding"] for item in sorted(data["data"], key=lambda x: x["index"])]

    def embed_one(self, text: str) -> list[float]:
        return self.embed([text])[0]
