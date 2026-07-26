"""LLM client implementations."""

import json
import time
import uuid
from typing import Any, AsyncIterator, Iterator

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import ConfigurationError, ProviderError
from devai.core.models import LLMResponse, Message, ToolCall, ToolDefinition
from devai.core.streaming import StreamChunk


def _retry_delay(attempt: int) -> float:
    return min(2 ** attempt, 8)


class LLMClient:
    """Provider-agnostic LLM client supporting OpenAI and Anthropic."""

    def __init__(self, config: DevAIConfig | None = None, **kwargs: Any) -> None:
        if config is None:
            config = DevAIConfig(**kwargs)
        self.config = config
        if self.config.is_mock:
            raise ConfigurationError(
                "Use MockLLMClient for mock provider instead of LLMClient"
            )
        if not self.config.api_key:
            raise ConfigurationError(
                "API key required. Set DEVAI_API_KEY or pass api_key to DevAIConfig."
            )

    def _build_messages(self, prompt: str | list[Message]) -> list[dict[str, Any]]:
        if isinstance(prompt, str):
            return [{"role": "user", "content": prompt}]
        return [
            {
                "role": m.role,
                "content": m.content,
                **({"name": m.name} if m.name else {}),
                **({"tool_call_id": m.tool_call_id} if m.tool_call_id else {}),
            }
            for m in prompt
        ]

    def complete(
        self,
        prompt: str | list[Message],
        *,
        system: str | None = None,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        messages = self._build_messages(prompt)
        if system:
            messages.insert(0, {"role": "system", "content": system})

        if self.config.provider == "openai":
            return self._complete_openai(
                messages, tools=tools, json_mode=json_mode,
                temperature=temperature, max_tokens=max_tokens,
            )
        if self.config.provider == "anthropic":
            return self._complete_anthropic(
                messages, system=system, tools=tools,
                temperature=temperature, max_tokens=max_tokens,
            )
        raise ConfigurationError(f"Unknown provider: {self.config.provider}")

    def _complete_openai(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        url = (self.config.base_url or "https://api.openai.com/v1") + "/chat/completions"
        body: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature or self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
        }
        if tools:
            body["tools"] = [t.to_schema() for t in tools]
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        data = self._request_with_retry(url, body)
        choice = data["choices"][0]
        message = choice["message"]
        tool_calls = None
        if message.get("tool_calls"):
            tool_calls = [
                ToolCall(
                    id=tc["id"],
                    name=tc["function"]["name"],
                    arguments=json.loads(tc["function"]["arguments"]),
                )
                for tc in message["tool_calls"]
            ]
        return LLMResponse(
            content=message.get("content") or "",
            model=data.get("model", self.config.model),
            usage=data.get("usage", {}),
            tool_calls=tool_calls,
            raw=data,
        )

    def _complete_anthropic(
        self,
        messages: list[dict[str, Any]],
        *,
        system: str | None = None,
        tools: list[ToolDefinition] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        url = (self.config.base_url or "https://api.anthropic.com/v1") + "/messages"
        # Filter system messages for Anthropic
        filtered = [m for m in messages if m["role"] != "system"]
        body: dict[str, Any] = {
            "model": self.config.model,
            "messages": filtered,
            "max_tokens": max_tokens or self.config.max_tokens,
            "temperature": temperature or self.config.temperature,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters or {"type": "object", "properties": {}},
                }
                for t in tools
            ]

        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
        }
        data = self._request_with_retry(url, body, headers=headers)
        content_parts = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        tool_calls = None
        tool_use_blocks = [b for b in data.get("content", []) if b.get("type") == "tool_use"]
        if tool_use_blocks:
            tool_calls = [
                ToolCall(id=b["id"], name=b["name"], arguments=b.get("input", {}))
                for b in tool_use_blocks
            ]
        return LLMResponse(
            content="".join(content_parts),
            model=data.get("model", self.config.model),
            usage={
                "prompt_tokens": data.get("usage", {}).get("input_tokens", 0),
                "completion_tokens": data.get("usage", {}).get("output_tokens", 0),
            },
            tool_calls=tool_calls,
            raw=data,
        )

    def _request_with_retry(
        self,
        url: str,
        body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        default_headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        if headers:
            default_headers.update(headers)

        last_error: Exception | None = None
        for attempt in range(self.config.max_retries):
            try:
                with httpx.Client(timeout=self.config.timeout) as client:
                    response = client.post(url, json=body, headers=default_headers)
                    if response.status_code >= 400:
                        raise ProviderError(
                            f"Provider error: {response.text}",
                            status_code=response.status_code,
                        )
                    return response.json()
            except (httpx.HTTPError, ProviderError) as e:
                last_error = e
                if attempt < self.config.max_retries - 1:
                    time.sleep(_retry_delay(attempt))
        raise ProviderError(f"Request failed after retries: {last_error}")

    def stream(
        self,
        prompt: str | list[Message],
        *,
        system: str | None = None,
    ) -> Iterator[StreamChunk]:
        """Stream completion chunks (OpenAI only)."""
        if self.config.provider != "openai":
            response = self.complete(prompt, system=system)
            yield StreamChunk(content=response.content, done=True)
            return

        messages = self._build_messages(prompt)
        if system:
            messages.insert(0, {"role": "system", "content": system})

        url = (self.config.base_url or "https://api.openai.com/v1") + "/chat/completions"
        body = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": True,
        }
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=self.config.timeout) as client:
            with client.stream("POST", url, json=body, headers=headers) as response:
                for line in response.iter_lines():
                    if not line.startswith("data: "):
                        continue
                    payload = line[6:]
                    if payload == "[DONE]":
                        yield StreamChunk(content="", done=True)
                        break
                    data = json.loads(payload)
                    delta = data["choices"][0].get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        yield StreamChunk(content=content)


class MockLLMClient:
    """Mock LLM client for testing without API keys."""

    def __init__(
        self,
        responses: list[str] | None = None,
        tool_calls: list[ToolCall] | None = None,
        config: DevAIConfig | None = None,
    ) -> None:
        self.responses = responses or ["Mock response"]
        self.default_tool_calls = tool_calls
        self.config = config or DevAIConfig(provider="mock")
        self._call_count = 0
        self.calls: list[dict[str, Any]] = []

    def complete(
        self,
        prompt: str | list[Message],
        *,
        system: str | None = None,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        self.calls.append({
            "prompt": prompt,
            "system": system,
            "tools": tools,
            "json_mode": json_mode,
        })
        idx = min(self._call_count, len(self.responses) - 1)
        content = self.responses[idx]
        self._call_count += 1
        return LLMResponse(
            content=content,
            model="mock",
            usage={"prompt_tokens": 10, "completion_tokens": 20},
            tool_calls=self.default_tool_calls,
        )

    def stream(
        self,
        prompt: str | list[Message],
        *,
        system: str | None = None,
    ) -> Iterator[StreamChunk]:
        response = self.complete(prompt, system=system)
        for char in response.content:
            yield StreamChunk(content=char)
        yield StreamChunk(content="", done=True)


class EmbeddingClient:
    """Client for generating text embeddings."""

    def __init__(self, config: DevAIConfig | None = None, **kwargs: Any) -> None:
        if config is None:
            config = DevAIConfig(**kwargs)
        self.config = config
        if not self.config.api_key and not self.config.is_mock:
            raise ConfigurationError("API key required for EmbeddingClient")

    def embed(self, texts: list[str]) -> list[list[float]]:
        if self.config.is_mock or not self.config.api_key:
            return [[0.1 * (i + 1)] * 8 for i in range(len(texts))]

        url = (self.config.base_url or "https://api.openai.com/v1") + "/embeddings"
        body = {"model": "text-embedding-3-small", "input": texts}
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=self.config.timeout) as client:
            response = client.post(url, json=body, headers=headers)
            if response.status_code >= 400:
                raise ProviderError(f"Embedding error: {response.text}", response.status_code)
            data = response.json()
            return [item["embedding"] for item in data["data"]]

    def embed_one(self, text: str) -> list[float]:
        return self.embed([text])[0]
