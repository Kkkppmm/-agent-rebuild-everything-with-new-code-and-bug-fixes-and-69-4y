"""LLM client for DevAI."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import APIError
from devai.core.models import LLMResponse, Message, Tool, ToolCall
from devai.core.retry import with_retry


class LLMClient:
    """OpenAI-compatible LLM client with streaming, tools, and JSON mode."""

    def __init__(self, config: DevAIConfig | None = None):
        self.config = config or DevAIConfig.from_env()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.require_api_key()}",
            "Content-Type": "application/json",
        }

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
            "model": kwargs.get("model", self.config.model),
            "messages": [m.to_dict() for m in messages],
            "temperature": kwargs.get("temperature", self.config.temperature),
            "stream": stream,
        }
        if self.config.max_tokens:
            payload["max_tokens"] = self.config.max_tokens
        if tools:
            payload["tools"] = [t.to_openai_schema() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _parse_response(self, data: dict[str, Any]) -> LLMResponse:
        choice = data["choices"][0]
        message = choice["message"]
        tool_calls = None
        if message.get("tool_calls"):
            tool_calls = [ToolCall.from_raw(tc["function"] | {"id": tc["id"]}) for tc in message["tool_calls"]]
        return LLMResponse(
            content=message.get("content"),
            tool_calls=tool_calls,
            model=data.get("model", ""),
            usage=data.get("usage", {}),
        )

    def chat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a chat completion request."""
        payload = self._build_payload(messages, tools=tools, json_mode=json_mode, **kwargs)

        def _request() -> LLMResponse:
            with httpx.Client(timeout=self.config.timeout) as client:
                resp = client.post(
                    f"{self.config.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
                if resp.status_code != 200:
                    raise APIError(
                        f"API request failed: {resp.status_code}",
                        status_code=resp.status_code,
                        body=resp.text,
                    )
                return self._parse_response(resp.json())

        return with_retry(
            _request,
            max_retries=self.config.max_retries,
            delay=self.config.retry_delay,
            retryable=lambda e: isinstance(e, APIError) and (e.status_code or 0) >= 500,
        )

    def stream(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        """Stream chat completion tokens."""
        payload = self._build_payload(messages, tools=tools, stream=True, **kwargs)

        with httpx.Client(timeout=self.config.timeout) as client:
            with client.stream(
                "POST",
                f"{self.config.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as resp:
                if resp.status_code != 200:
                    raise APIError(
                        f"API request failed: {resp.status_code}",
                        status_code=resp.status_code,
                    )
                for line in resp.iter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0].get("delta", {})
                    if content := delta.get("content"):
                        yield content

    async def achat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> LLMResponse:
        """Async chat completion."""
        payload = self._build_payload(messages, tools=tools, json_mode=json_mode, **kwargs)

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            resp = await client.post(
                f"{self.config.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            if resp.status_code != 200:
                raise APIError(
                    f"API request failed: {resp.status_code}",
                    status_code=resp.status_code,
                    body=resp.text,
                )
            return self._parse_response(resp.json())

    async def astream(
        self,
        messages: list[Message],
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Async streaming chat completion."""
        payload = self._build_payload(messages, stream=True, **kwargs)

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.config.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as resp:
                if resp.status_code != 200:
                    raise APIError(f"API request failed: {resp.status_code}")
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0].get("delta", {})
                    if content := delta.get("content"):
                        yield content


class MockLLMClient:
    """Deterministic mock LLM client for testing without API keys."""

    def __init__(self, responses: list[str] | None = None):
        self.responses = responses or ["Mock response from DevAI."]
        self._call_count = 0
        self.last_messages: list[Message] = []

    def chat(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> LLMResponse:
        self.last_messages = messages
        idx = min(self._call_count, len(self.responses) - 1)
        self._call_count += 1
        content = self.responses[idx]
        if json_mode and not content.strip().startswith("{"):
            content = json.dumps({"result": content})
        return LLMResponse(content=content, model="mock-model")

    def stream(self, messages: list[Message], **kwargs: Any) -> Iterator[str]:
        response = self.chat(messages, **kwargs)
        for word in (response.content or "").split():
            yield word + " "

    async def achat(self, messages: list[Message], **kwargs: Any) -> LLMResponse:
        return self.chat(messages, **kwargs)

    async def astream(self, messages: list[Message], **kwargs: Any) -> AsyncIterator[str]:
        for token in self.stream(messages, **kwargs):
            yield token
