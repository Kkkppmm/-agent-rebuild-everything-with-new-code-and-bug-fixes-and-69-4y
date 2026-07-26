"""LLM client implementations."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError, RateLimitError
from devai.core.models import Message, Role, Tool, ToolCall
from devai.core.retry import with_retry


class LLMClient:
    """OpenAI-compatible LLM client with streaming, tools, and JSON mode."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig.from_env()
        if not self.config.api_key:
            raise LLMError(
                "API key required. Set DEVAI_API_KEY or OPENAI_API_KEY environment variable."
            )
        self._client = httpx.Client(
            base_url=self.config.base_url,
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            timeout=self.config.timeout,
        )

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
            "max_tokens": kwargs.pop("max_tokens", self.config.max_tokens),
            "stream": stream,
            **kwargs,
        }
        if tools:
            payload["tools"] = [t.to_openai_schema() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 429:
            raise RateLimitError("Rate limit exceeded")
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
        """Send a chat completion request and return the assistant message."""

        def _call() -> Message:
            payload = self._build_payload(
                messages, tools=tools, json_mode=json_mode, stream=False, **kwargs
            )
            data = self._handle_response(self._client.post("/chat/completions", json=payload))
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

        return with_retry(
            _call,
            max_retries=self.config.max_retries,
            delay=self.config.retry_delay,
        )

    def stream(
        self,
        messages: list[Message],
        **kwargs: Any,
    ) -> Iterator[str]:
        """Stream chat completion tokens."""
        payload = self._build_payload(messages, stream=True, **kwargs)
        with self._client.stream("POST", "/chat/completions", json=payload) as response:
            if response.status_code >= 400:
                raise LLMError(f"API error {response.status_code}")
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

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a list of texts."""
        response = self._client.post(
            "/embeddings",
            json={"model": self.config.embedding_model, "input": texts},
        )
        data = self._handle_response(response)
        return [item["embedding"] for item in data["data"]]

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> LLMClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class MockLLMClient:
    """Deterministic mock LLM for testing without API keys."""

    def __init__(
        self,
        responses: list[str] | None = None,
        tool_responses: list[Message] | None = None,
    ) -> None:
        self.responses = responses or ["Mock response"]
        self.tool_responses = tool_responses or []
        self._call_count = 0
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
        if self.tool_responses and self._call_count < len(self.tool_responses):
            msg = self.tool_responses[self._call_count]
            self._call_count += 1
            return msg
        idx = min(self._call_count, len(self.responses) - 1)
        content = self.responses[idx]
        self._call_count += 1
        if json_mode and not content.strip().startswith("{"):
            content = json.dumps({"result": content})
        return Message(role=Role.ASSISTANT, content=content)

    def stream(self, messages: list[Message], **kwargs: Any) -> Iterator[str]:
        msg = self.complete(messages, **kwargs)
        for word in msg.content.split():
            yield word + " "

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[float(i) / max(len(text), 1) for i in range(8)] for text in texts]

    def close(self) -> None:
        pass
