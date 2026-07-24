"""LLM and embedding clients with retry and streaming support."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError, RateLimitError
from devai.core.models import Message, Role, Tool, ToolCall


class LLMClient:
    """OpenAI-compatible LLM client with retries, JSON mode, and streaming."""

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
        }
        if tools:
            payload["tools"] = [t.to_dict() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        payload.update(kwargs)
        return payload

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.config.base_url.rstrip('/')}/chat/completions"
        last_error: Exception | None = None

        for attempt in range(self.config.max_retries):
            try:
                with httpx.Client(timeout=self.config.timeout) as client:
                    response = client.post(url, headers=self._headers(), json=payload)
                    if response.status_code == 429:
                        raise RateLimitError(f"Rate limited: {response.text}")
                    if response.status_code >= 400:
                        raise LLMError(f"API error {response.status_code}: {response.text}")
                    return response.json()
            except RateLimitError:
                raise
            except Exception as exc:
                last_error = exc
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (2**attempt))

        raise LLMError(f"Request failed after {self.config.max_retries} retries: {last_error}")

    def _parse_response(self, data: dict[str, Any]) -> Message:
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
            role=Role(choice["role"]),
            content=choice.get("content") or "",
            tool_calls=tool_calls,
        )

    def chat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Message:
        """Send a chat completion request and return the assistant message."""
        payload = self._build_payload(messages, tools=tools, json_mode=json_mode, **kwargs)
        data = self._request(payload)
        return self._parse_response(data)

    def complete(self, prompt: str, *, system: str | None = None, **kwargs: Any) -> str:
        """Simple text completion from a prompt."""
        messages = []
        if system:
            messages.append(Message(role=Role.SYSTEM, content=system))
        messages.append(Message(role=Role.USER, content=prompt))
        return self.chat(messages, **kwargs).content

    def stream(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        """Stream text chunks from a chat completion."""
        payload = self._build_payload(messages, tools=tools, stream=True, **kwargs)
        url = f"{self.config.base_url.rstrip('/')}/chat/completions"

        with httpx.Client(timeout=self.config.timeout) as client:
            with client.stream("POST", url, headers=self._headers(), json=payload) as response:
                if response.status_code >= 400:
                    raise LLMError(f"Stream error {response.status_code}: {response.read()}")
                for line in response.iter_lines():
                    if not line.startswith("data: "):
                        continue
                    chunk_data = line[6:]
                    if chunk_data.strip() == "[DONE]":
                        break
                    try:
                        chunk = json.loads(chunk_data)
                        delta = chunk["choices"][0]["delta"]
                        if content := delta.get("content"):
                            yield content
                    except (json.JSONDecodeError, KeyError, IndexError):
                        continue


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
        self.history: list[list[Message]] = []

    def chat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Message:
        self.history.append(list(messages))
        if self.tool_responses and self._call_count < len(self.tool_responses):
            msg = self.tool_responses[self._call_count]
            self._call_count += 1
            return msg

        idx = min(self._call_count, len(self.responses) - 1)
        content = self.responses[idx]
        self._call_count += 1

        if json_mode and not content.strip().startswith("{"):
            content = json.dumps({"result": content})

        if tools and "TOOL:" in content:
            parts = content.split("TOOL:", 1)[1].strip()
            name, args_str = parts.split("|", 1)
            return Message(
                role=Role.ASSISTANT,
                content="",
                tool_calls=[
                    ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name=name.strip(), arguments=json.loads(args_str))
                ],
            )

        return Message(role=Role.ASSISTANT, content=content)

    def complete(self, prompt: str, *, system: str | None = None, **kwargs: Any) -> str:
        messages = []
        if system:
            messages.append(Message(role=Role.SYSTEM, content=system))
        messages.append(Message(role=Role.USER, content=prompt))
        return self.chat(messages, **kwargs).content

    def stream(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        content = self.chat(messages, tools=tools, **kwargs).content
        for word in content.split():
            yield word + " "


class EmbeddingClient:
    """OpenAI-compatible embedding client."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig()

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def embed(self, texts: list[str], *, model: str | None = None) -> list[list[float]]:
        """Generate embeddings for a list of texts."""
        url = f"{self.config.base_url.rstrip('/')}/embeddings"
        payload = {
            "model": model or self.config.embedding_model,
            "input": texts,
        }
        with httpx.Client(timeout=self.config.timeout) as client:
            response = client.post(url, headers=self._headers(), json=payload)
            if response.status_code >= 400:
                raise LLMError(f"Embedding error {response.status_code}: {response.text}")
            data = response.json()
            return [item["embedding"] for item in sorted(data["data"], key=lambda x: x["index"])]

    def embed_one(self, text: str, **kwargs: Any) -> list[float]:
        """Generate an embedding for a single text."""
        return self.embed([text], **kwargs)[0]
