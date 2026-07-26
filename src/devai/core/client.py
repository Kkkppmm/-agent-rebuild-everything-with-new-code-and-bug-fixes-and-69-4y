"""LLM and embedding clients."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError, RateLimitError
from devai.core.models import Message, Role, Tool, ToolCall
from devai.core.retry import with_retry


class LLMClient:
    """OpenAI-compatible LLM client with streaming, JSON mode, and tool calling."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig.from_env()
        self._client = httpx.Client(
            base_url=self.config.base_url,
            headers=self._headers(),
            timeout=self.config.timeout,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

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
            "model": kwargs.pop("model", self.config.model),
            "messages": [m.to_dict() for m in messages],
            "temperature": kwargs.pop("temperature", self.config.temperature),
            "stream": stream,
        }
        if self.config.max_tokens:
            payload["max_tokens"] = self.config.max_tokens
        if tools:
            payload["tools"] = [t.to_openai_schema() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        payload.update(kwargs)
        return payload

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 429:
            raise RateLimitError(f"Rate limit exceeded: {response.text}")
        if response.status_code >= 400:
            raise LLMError(f"API error {response.status_code}: {response.text}")
        return response.json()

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Message:
        payload = self._build_payload(messages, tools=tools, json_mode=json_mode, **kwargs)

        def _call() -> dict[str, Any]:
            return self._handle_response(self._client.post("/chat/completions", json=payload))

        data = with_retry(
            _call,
            max_retries=self.config.max_retries,
            delay=self.config.retry_delay,
        )
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
        return Message(
            role=Role.ASSISTANT,
            content=choice.get("content") or "",
            tool_calls=tool_calls,
        )

    def stream(
        self,
        messages: list[Message],
        **kwargs: Any,
    ) -> Iterator[str]:
        payload = self._build_payload(messages, stream=True, **kwargs)
        with self._client.stream("POST", "/chat/completions", json=payload) as response:
            if response.status_code >= 400:
                raise LLMError(f"API error {response.status_code}: {response.read().decode()}")
            for line in response.iter_lines():
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str.strip() == "[DONE]":
                    break
                chunk = json.loads(data_str)
                delta = chunk["choices"][0].get("delta", {})
                if content := delta.get("content"):
                    yield content

    def complete_json(self, messages: list[Message], **kwargs: Any) -> dict[str, Any]:
        response = self.complete(messages, json_mode=True, **kwargs)
        try:
            return json.loads(response.content)
        except json.JSONDecodeError as exc:
            from devai.core.exceptions import ParseError

            raise ParseError(f"Failed to parse JSON response: {response.content}") from exc

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> LLMClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class MockLLMClient:
    """Deterministic mock client for testing without API keys."""

    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = responses or ["Mock response from DevAI."]
        self._index = 0
        self.calls: list[list[Message]] = []

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Message:
        self.calls.append(messages)
        content = self.responses[self._index % len(self.responses)]
        self._index += 1
        if json_mode and not content.strip().startswith("{"):
            content = json.dumps({"result": content})
        return Message(role=Role.ASSISTANT, content=content)

    def stream(self, messages: list[Message], **kwargs: Any) -> Iterator[str]:
        response = self.complete(messages, **kwargs)
        for word in response.content.split():
            yield word + " "

    def complete_json(self, messages: list[Message], **kwargs: Any) -> dict[str, Any]:
        response = self.complete(messages, json_mode=True, **kwargs)
        return json.loads(response.content)

    def close(self) -> None:
        pass


class EmbeddingClient:
    """OpenAI-compatible embedding client."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig.from_env()
        self._client = httpx.Client(
            base_url=self.config.base_url,
            headers=self._headers(),
            timeout=self.config.timeout,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def embed(self, texts: list[str], *, model: str | None = None) -> list[list[float]]:
        payload = {
            "model": model or self.config.embedding_model,
            "input": texts,
        }

        def _call() -> dict[str, Any]:
            response = self._client.post("/embeddings", json=payload)
            if response.status_code == 429:
                raise RateLimitError(f"Rate limit exceeded: {response.text}")
            if response.status_code >= 400:
                raise LLMError(f"API error {response.status_code}: {response.text}")
            return response.json()

        data = with_retry(
            _call,
            max_retries=self.config.max_retries,
            delay=self.config.retry_delay,
        )
        return [item["embedding"] for item in data["data"]]

    def close(self) -> None:
        self._client.close()
