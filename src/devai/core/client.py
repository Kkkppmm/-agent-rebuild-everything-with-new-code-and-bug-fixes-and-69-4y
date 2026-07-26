"""LLM and embedding clients."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import APIError, AuthenticationError, RateLimitError
from devai.core.models import Message, Response, ToolCall, ToolDefinition


class LLMClient:
    """OpenAI-compatible LLM client with retries, streaming, and JSON mode."""

    def __init__(self, config: DevAIConfig | None = None):
        self.config = config or DevAIConfig()

    def _headers(self) -> dict[str, str]:
        self.config.validate()
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        headers.update(self.config.extra_headers)
        return headers

    def _build_payload(
        self,
        messages: list[dict[str, Any] | Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        stream: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        msgs = [m.to_dict() if isinstance(m, Message) else m for m in messages]
        payload: dict[str, Any] = {
            "model": kwargs.get("model", self.config.model),
            "messages": msgs,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "temperature": kwargs.get("temperature", self.config.temperature),
            "stream": stream,
        }
        if tools:
            payload["tools"] = [t.to_dict() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.config.base_url.rstrip('/')}/{path.lstrip('/')}"
        last_error: Exception | None = None

        for attempt in range(self.config.max_retries):
            try:
                with httpx.Client(timeout=self.config.timeout) as client:
                    response = client.request(method, url, headers=self._headers(), json=payload)
                if response.status_code == 401:
                    raise AuthenticationError("Invalid API key", status_code=401)
                if response.status_code == 429:
                    if attempt < self.config.max_retries - 1:
                        time.sleep(self.config.retry_delay * (2**attempt))
                        continue
                    raise RateLimitError("Rate limit exceeded", status_code=429)
                if response.status_code >= 400:
                    raise APIError(
                        f"API error: {response.status_code}",
                        status_code=response.status_code,
                        body=response.text,
                    )
                return response.json()
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_error = exc
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (2**attempt))
                    continue
                raise APIError(f"Request failed: {exc}") from exc

        raise APIError(f"Request failed after retries: {last_error}")

    def _parse_response(self, data: dict[str, Any]) -> Response:
        choice = data["choices"][0]
        message = choice["message"]
        tool_calls = []
        if message.get("tool_calls"):
            tool_calls = [ToolCall.from_dict(tc) for tc in message["tool_calls"]]
        return Response(
            content=message.get("content"),
            tool_calls=tool_calls,
            model=data.get("model", ""),
            usage=data.get("usage", {}),
            finish_reason=choice.get("finish_reason"),
            raw=data,
        )

    def chat(
        self,
        messages: list[dict[str, Any] | Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Response:
        """Send a chat completion request."""
        payload = self._build_payload(messages, tools=tools, json_mode=json_mode, **kwargs)
        data = self._request("POST", "/chat/completions", payload)
        return self._parse_response(data)

    def stream(
        self,
        messages: list[dict[str, Any] | Message],
        **kwargs: Any,
    ) -> Iterator[str]:
        """Stream chat completion tokens."""
        payload = self._build_payload(messages, stream=True, **kwargs)
        url = f"{self.config.base_url.rstrip('/')}/chat/completions"

        with httpx.Client(timeout=self.config.timeout) as client:
            with client.stream("POST", url, headers=self._headers(), json=payload) as response:
                if response.status_code >= 400:
                    raise APIError(f"Stream error: {response.status_code}", status_code=response.status_code)
                for line in response.iter_lines():
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

    def chat_json(
        self,
        messages: list[dict[str, Any] | Message],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Chat with JSON mode and parse the response."""
        response = self.chat(messages, json_mode=True, **kwargs)
        if not response.content:
            return {}
        return json.loads(response.content)


class MockLLMClient:
    """Mock LLM client for testing without API calls."""

    def __init__(
        self,
        responses: list[str] | None = None,
        tool_responses: list[list[ToolCall]] | None = None,
    ):
        self.responses = list(responses or ["Mock response"])
        self.tool_responses = list(tool_responses or [])
        self._call_count = 0
        self.call_history: list[list[dict[str, Any] | Message]] = []

    def chat(
        self,
        messages: list[dict[str, Any] | Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Response:
        self.call_history.append(messages)
        idx = min(self._call_count, len(self.responses) - 1)

        if self.tool_responses and self._call_count < len(self.tool_responses):
            tcs = self.tool_responses[self._call_count]
            self._call_count += 1
            return Response(content=None, tool_calls=tcs, model="mock", finish_reason="tool_calls")

        content = self.responses[idx]
        if json_mode and not content.strip().startswith("{"):
            content = json.dumps({"result": content})

        self._call_count += 1
        return Response(content=content, model="mock", finish_reason="stop")

    def stream(
        self,
        messages: list[dict[str, Any] | Message],
        **kwargs: Any,
    ) -> Iterator[str]:
        response = self.chat(messages, **kwargs)
        if response.content:
            for word in response.content.split():
                yield word + " "

    def chat_json(
        self,
        messages: list[dict[str, Any] | Message],
        **kwargs: Any,
    ) -> dict[str, Any]:
        response = self.chat(messages, json_mode=True, **kwargs)
        return json.loads(response.content or "{}")

    def reset(self) -> None:
        self._call_count = 0
        self.call_history.clear()


class EmbeddingClient:
    """Client for generating text embeddings."""

    def __init__(self, config: DevAIConfig | None = None):
        self.config = config or DevAIConfig()
        self._llm = LLMClient(self.config)

    def embed(self, texts: list[str], **kwargs: Any) -> list[list[float]]:
        """Generate embeddings for a list of texts."""
        model = kwargs.get("model", self.config.embedding_model)
        payload = {"model": model, "input": texts}
        data = self._llm._request("POST", "/embeddings", payload)
        sorted_data = sorted(data["data"], key=lambda x: x["index"])
        return [item["embedding"] for item in sorted_data]

    def embed_one(self, text: str, **kwargs: Any) -> list[float]:
        """Generate embedding for a single text."""
        return self.embed([text], **kwargs)[0]
