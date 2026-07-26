"""LLM client implementations."""

import json
from typing import Any, AsyncIterator, Iterator, Optional

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError
from devai.core.models import Message, Role, Tool, ToolCall
from devai.core.retry import with_retry


class LLMClient:
    """OpenAI-compatible LLM client with streaming, tools, and JSON mode."""

    def __init__(self, config: Optional[DevAIConfig] = None) -> None:
        self.config = config or DevAIConfig()

    def _headers(self) -> dict[str, str]:
        if not self.config.api_key:
            raise LLMError("API key not configured. Set OPENAI_API_KEY or pass api_key.")
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

    def _build_payload(
        self,
        messages: list[Message],
        tools: Optional[list[Tool]] = None,
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
            payload["tools"] = [t.to_dict() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _parse_response(self, data: dict[str, Any]) -> Message:
        choice = data["choices"][0]
        msg = choice["message"]
        tool_calls = None
        if msg.get("tool_calls"):
            tool_calls = []
            for tc in msg["tool_calls"]:
                args = tc["function"]["arguments"]
                if isinstance(args, str):
                    args = json.loads(args)
                tool_calls.append(
                    ToolCall(
                        id=tc["id"],
                        name=tc["function"]["name"],
                        arguments=args,
                    )
                )
        return Message(
            role=Role(msg["role"]),
            content=msg.get("content") or "",
            tool_calls=tool_calls,
        )

    def complete(
        self,
        messages: list[Message],
        tools: Optional[list[Tool]] = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Message:
        payload = self._build_payload(messages, tools=tools, json_mode=json_mode, **kwargs)

        def _call() -> Message:
            with httpx.Client(timeout=self.config.timeout) as client:
                resp = client.post(
                    f"{self.config.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
                if resp.status_code != 200:
                    raise LLMError(f"API error {resp.status_code}: {resp.text}")
                return self._parse_response(resp.json())

        return with_retry(
            _call,
            max_retries=self.config.max_retries,
            delay=self.config.retry_delay,
        )

    def stream(
        self,
        messages: list[Message],
        tools: Optional[list[Tool]] = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        payload = self._build_payload(messages, tools=tools, stream=True, **kwargs)

        with httpx.Client(timeout=self.config.timeout) as client:
            with client.stream(
                "POST",
                f"{self.config.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as resp:
                if resp.status_code != 200:
                    raise LLMError(f"API error {resp.status_code}: {resp.read().decode()}")
                for line in resp.iter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    chunk = line[6:]
                    if chunk == "[DONE]":
                        break
                    data = json.loads(chunk)
                    delta = data["choices"][0]["delta"]
                    if "content" in delta and delta["content"]:
                        yield delta["content"]

    async def acomplete(
        self,
        messages: list[Message],
        tools: Optional[list[Tool]] = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Message:
        payload = self._build_payload(messages, tools=tools, json_mode=json_mode, **kwargs)

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            resp = await client.post(
                f"{self.config.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            if resp.status_code != 200:
                raise LLMError(f"API error {resp.status_code}: {resp.text}")
            return self._parse_response(resp.json())

    async def astream(
        self,
        messages: list[Message],
        tools: Optional[list[Tool]] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        payload = self._build_payload(messages, tools=tools, stream=True, **kwargs)

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.config.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as resp:
                if resp.status_code != 200:
                    raise LLMError(f"API error {resp.status_code}: {await resp.aread()}")
                async for line in resp.aiter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    chunk = line[6:]
                    if chunk == "[DONE]":
                        break
                    data = json.loads(chunk)
                    delta = data["choices"][0]["delta"]
                    if "content" in delta and delta["content"]:
                        yield delta["content"]


class MockLLMClient:
    """Deterministic mock client for testing without API calls."""

    def __init__(
        self,
        responses: Optional[list[str]] = None,
        tool_calls: Optional[list[ToolCall]] = None,
    ) -> None:
        self.responses = responses or ["Mock response"]
        self.tool_calls = tool_calls
        self._call_count = 0
        self.calls: list[list[Message]] = []

    def complete(
        self,
        messages: list[Message],
        tools: Optional[list[Tool]] = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Message:
        self.calls.append(messages)
        idx = min(self._call_count, len(self.responses) - 1)
        self._call_count += 1
        return Message(
            role=Role.ASSISTANT,
            content=self.responses[idx],
            tool_calls=self.tool_calls,
        )

    def stream(
        self,
        messages: list[Message],
        tools: Optional[list[Tool]] = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        msg = self.complete(messages, tools=tools, **kwargs)
        for char in msg.content:
            yield char

    async def acomplete(
        self,
        messages: list[Message],
        tools: Optional[list[Tool]] = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Message:
        return self.complete(messages, tools=tools, json_mode=json_mode, **kwargs)

    async def astream(
        self,
        messages: list[Message],
        tools: Optional[list[Tool]] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        for chunk in self.stream(messages, tools=tools, **kwargs):
            yield chunk
