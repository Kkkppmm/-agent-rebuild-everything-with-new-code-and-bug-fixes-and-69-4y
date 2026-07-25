"""OpenAI-compatible LLM client with retries and tool support."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import APIError, AuthenticationError, ConfigurationError, RateLimitError
from devai.core.models import CompletionResponse, Message, Tool, ToolCall


class LLMClient:
    """Async HTTP client for OpenAI-compatible chat completion APIs."""

    def __init__(self, config: DevAIConfig | None = None):
        self.config = config or DevAIConfig()
        if not self.config.api_key:
            raise ConfigurationError(
                "API key required. Set OPENAI_API_KEY or pass api_key to DevAIConfig."
            )
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                **self.config.extra_headers,
            },
            timeout=self.config.timeout,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> LLMClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def chat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool | None = None,
        model: str | None = None,
    ) -> CompletionResponse:
        """Send a chat completion request."""
        payload = self._build_payload(
            messages, tools, temperature, max_tokens, json_mode, model
        )
        data = await self._request_with_retry("/chat/completions", payload)
        return self._parse_response(data)

    def chat_sync(
        self,
        messages: list[Message],
        **kwargs: Any,
    ) -> CompletionResponse:
        """Synchronous wrapper around chat()."""
        return asyncio.run(self.chat(messages, **kwargs))

    def _build_payload(
        self,
        messages: list[Message],
        tools: list[Tool] | None,
        temperature: float | None,
        max_tokens: int | None,
        json_mode: bool | None,
        model: str | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model or self.config.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature if temperature is not None else self.config.temperature,
        }
        if max_tokens is not None or self.config.max_tokens is not None:
            payload["max_tokens"] = max_tokens or self.config.max_tokens
        if tools:
            payload["tools"] = [t.to_dict() for t in tools]
        use_json = json_mode if json_mode is not None else self.config.json_mode
        if use_json:
            payload["response_format"] = {"type": "json_object"}
        return payload

    async def _request_with_retry(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self.config.max_retries):
            try:
                response = await self._client.post(path, json=payload)
                if response.status_code == 429:
                    raise RateLimitError(
                        "Rate limit exceeded",
                        status_code=429,
                        body=response.text,
                    )
                if response.status_code == 401:
                    raise AuthenticationError(
                        "Authentication failed",
                        status_code=401,
                        body=response.text,
                    )
                if response.status_code >= 400:
                    raise APIError(
                        f"API error: {response.status_code}",
                        status_code=response.status_code,
                        body=response.text,
                    )
                return response.json()
            except (httpx.TimeoutException, httpx.ConnectError, RateLimitError) as e:
                last_error = e
                if attempt < self.config.max_retries - 1:
                    delay = self.config.retry_delay * (2**attempt)
                    await asyncio.sleep(delay)
        raise APIError(f"Request failed after {self.config.max_retries} retries: {last_error}")

    def _parse_response(self, data: dict[str, Any]) -> CompletionResponse:
        choice = data["choices"][0]
        message = choice["message"]
        tool_calls = None
        if message.get("tool_calls"):
            tool_calls = []
            for tc in message["tool_calls"]:
                args = tc["function"]["arguments"]
                if isinstance(args, str):
                    args = json.loads(args)
                tool_calls.append(
                    ToolCall(id=tc["id"], name=tc["function"]["name"], arguments=args)
                )
        return CompletionResponse(
            content=message.get("content") or "",
            tool_calls=tool_calls,
            finish_reason=choice.get("finish_reason"),
            usage=data.get("usage"),
        )
