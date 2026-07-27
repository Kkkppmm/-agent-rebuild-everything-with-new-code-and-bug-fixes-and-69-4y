"""LLM and embedding clients."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError, RateLimitError
from devai.core.models import Message, ToolCall, ToolDefinition
from devai.core.retry import with_retry


class LLMClient:
    """OpenAI-compatible LLM client with sync, async, and streaming support."""

    def __init__(self, config: DevAIConfig | None = None, **kwargs: Any) -> None:
        if config is None:
            config = DevAIConfig(**kwargs)
        self.config = config
        self._client = httpx.Client(
            base_url=config.base_url,
            headers={"Authorization": f"Bearer {config.api_key}"},
            timeout=config.timeout,
        )
        self._async_client = httpx.AsyncClient(
            base_url=config.base_url,
            headers={"Authorization": f"Bearer {config.api_key}"},
            timeout=config.timeout,
        )

    def complete(
        self,
        messages: list[Message],
        *,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
    ) -> Message:
        def _call() -> Message:
            return self._parse_response(self._post_chat(messages, model, temperature, max_tokens, tools, json_mode))

        return with_retry(
            _call,
            max_retries=self.config.max_retries,
            delay=self.config.retry_delay,
            retryable=(RateLimitError,),
        )

    async def acomplete(
        self,
        messages: list[Message],
        *,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
    ) -> Message:
        data = await self._apost_chat(messages, model, temperature, max_tokens, tools, json_mode)
        return self._parse_response(data)

    def stream(
        self,
        messages: list[Message],
        *,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        payload = self._build_payload(messages, model, temperature, max_tokens)
        payload["stream"] = True
        with self._client.stream("POST", "/chat/completions", json=payload) as resp:
            self._check_response(resp)
            for line in resp.iter_lines():
                if not line.startswith("data: "):
                    continue
                chunk = line[6:]
                if chunk.strip() == "[DONE]":
                    break
                delta = json.loads(chunk)
                content = delta.get("choices", [{}])[0].get("delta", {}).get("content")
                if content:
                    yield content

    async def astream(
        self,
        messages: list[Message],
        *,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        payload = self._build_payload(messages, model, temperature, max_tokens)
        payload["stream"] = True
        async with self._async_client.stream("POST", "/chat/completions", json=payload) as resp:
            self._check_response(resp)
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                chunk = line[6:]
                if chunk.strip() == "[DONE]":
                    break
                delta = json.loads(chunk)
                content = delta.get("choices", [{}])[0].get("delta", {}).get("content")
                if content:
                    yield content

    def _post_chat(
        self,
        messages: list[Message],
        model: str | None,
        temperature: float | None,
        max_tokens: int | None,
        tools: list[ToolDefinition] | None,
        json_mode: bool,
    ) -> dict[str, Any]:
        payload = self._build_payload(messages, model, temperature, max_tokens, tools, json_mode)
        resp = self._client.post("/chat/completions", json=payload)
        self._check_response(resp)
        return resp.json()

    async def _apost_chat(
        self,
        messages: list[Message],
        model: str | None,
        temperature: float | None,
        max_tokens: int | None,
        tools: list[ToolDefinition] | None,
        json_mode: bool,
    ) -> dict[str, Any]:
        payload = self._build_payload(messages, model, temperature, max_tokens, tools, json_mode)
        resp = await self._async_client.post("/chat/completions", json=payload)
        self._check_response(resp)
        return resp.json()

    def _build_payload(
        self,
        messages: list[Message],
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model or self.config.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
        }
        if tools:
            payload["tools"] = [t.to_dict() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _parse_response(self, data: dict[str, Any]) -> Message:
        choice = data["choices"][0]["message"]
        tool_calls = None
        if choice.get("tool_calls"):
            tool_calls = []
            for tc in choice["tool_calls"]:
                fn = tc["function"]
                tool_calls.append(
                    ToolCall(
                        id=tc["id"],
                        name=fn["name"],
                        arguments=json.loads(fn["arguments"]),
                    )
                )
        return Message(
            role=choice["role"],
            content=choice.get("content") or "",
            tool_calls=tool_calls,
        )

    def _check_response(self, resp: httpx.Response) -> None:
        if resp.status_code == 429:
            raise RateLimitError(f"Rate limit exceeded: {resp.text}")
        if resp.status_code >= 400:
            raise LLMError(f"API error {resp.status_code}: {resp.text}")

    def close(self) -> None:
        self._client.close()

    async def aclose(self) -> None:
        await self._async_client.aclose()


class MockLLMClient:
    """Deterministic mock client for testing without API keys."""

    def __init__(self, responses: list[str] | None = None, enable_tool_calls: bool = False) -> None:
        self.responses = responses or [
            "This code looks good overall. Consider adding error handling.",
            "The function divides two numbers. Add a zero-check for `b`.",
            "Bug: division by zero when b=0. Fix: `if b == 0: raise ValueError(...)`.",
        ]
        self._call_count = 0
        self.enable_tool_calls = enable_tool_calls
        self.config = DevAIConfig(api_key="mock")

    def complete(
        self,
        messages: list[Message],
        *,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
    ) -> Message:
        content = self.responses[self._call_count % len(self.responses)]
        self._call_count += 1

        if tools and self.enable_tool_calls and self._call_count % 2 == 1:
            args: dict[str, Any] = {}
            for tool in tools:
                required = tool.parameters.get("required", [])
                props = tool.parameters.get("properties", {})
                for param in required:
                    ptype = props.get(param, {}).get("type", "string")
                    args[param] = "" if ptype == "string" else 0
                break
            return Message(
                role="assistant",
                content="",
                tool_calls=[
                    ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name=tools[0].name, arguments=args)
                ],
            )

        if json_mode and not content.strip().startswith("{"):
            content = json.dumps({"result": content, "status": "ok"})

        return Message(role="assistant", content=content)

    async def acomplete(self, messages: list[Message], **kwargs: Any) -> Message:
        return self.complete(messages, **kwargs)

    def stream(self, messages: list[Message], **kwargs: Any) -> Iterator[str]:
        content = self.complete(messages, **kwargs).content
        for word in content.split():
            yield word + " "

    async def astream(self, messages: list[Message], **kwargs: Any) -> AsyncIterator[str]:
        for chunk in self.stream(messages, **kwargs):
            yield chunk


class EmbeddingClient:
    """Client for text embedding APIs."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig()
        self._client = httpx.Client(
            base_url=self.config.base_url,
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            timeout=self.config.timeout,
        )

    def embed(self, texts: list[str], model: str | None = None) -> list[list[float]]:
        resp = self._client.post(
            "/embeddings",
            json={"model": model or self.config.embedding_model, "input": texts},
        )
        if resp.status_code >= 400:
            raise LLMError(f"Embedding error {resp.status_code}: {resp.text}")
        data = resp.json()
        return [item["embedding"] for item in sorted(data["data"], key=lambda x: x["index"])]

    def embed_one(self, text: str, model: str | None = None) -> list[float]:
        return self.embed([text], model=model)[0]

    def close(self) -> None:
        self._client.close()
