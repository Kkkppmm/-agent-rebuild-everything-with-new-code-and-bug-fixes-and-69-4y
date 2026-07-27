"""LLM and embedding clients with sync/async and streaming support."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError, RateLimitError
from devai.core.models import Message, ToolCall, ToolDefinition
from devai.core.retries import async_with_retries, with_retries


class LLMClient:
    """OpenAI-compatible LLM client."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig.from_env()

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Message:
        def _call() -> Message:
            return self._sync_request(
                messages,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=False,
            )

        return with_retries(
            _call,
            max_retries=self.config.max_retries,
            retry_delay=self.config.retry_delay,
        )

    def stream(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        payload = self._build_payload(
            messages,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
        )
        with httpx.Client(timeout=self.config.timeout) as client, client.stream(
            "POST",
            f"{self.config.base_url.rstrip('/')}/chat/completions",
            headers=self._headers(),
            json=payload,
        ) as response:
            self._raise_for_status(response)
            for line in response.iter_lines():
                chunk = _parse_stream_line(line)
                if chunk:
                    yield chunk

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Message:
        async def _call() -> Message:
            return await self._async_request(
                messages,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=False,
            )

        return await async_with_retries(
            _call,
            max_retries=self.config.max_retries,
            retry_delay=self.config.retry_delay,
        )

    async def astream(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        payload = self._build_payload(
            messages,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
        )
        async with httpx.AsyncClient(timeout=self.config.timeout) as client, client.stream(
            "POST",
            f"{self.config.base_url.rstrip('/')}/chat/completions",
            headers=self._headers(),
            json=payload,
        ) as response:
            await self._araise_for_status(response)
            async for line in response.aiter_lines():
                chunk = _parse_stream_line(line)
                if chunk:
                    yield chunk

    def _sync_request(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None,
        json_mode: bool,
        temperature: float | None,
        max_tokens: int | None,
        stream: bool,
    ) -> Message:
        payload = self._build_payload(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
        )
        with httpx.Client(timeout=self.config.timeout) as client:
            response = client.post(
                f"{self.config.base_url.rstrip('/')}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            self._raise_for_status(response)
            return _parse_response(response.json())

    async def _async_request(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None,
        json_mode: bool,
        temperature: float | None,
        max_tokens: int | None,
        stream: bool,
    ) -> Message:
        payload = self._build_payload(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
        )
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(
                f"{self.config.base_url.rstrip('/')}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            await self._araise_for_status(response)
            return _parse_response(response.json())

    def _build_payload(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream: bool = False,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.config.max_tokens,
            "stream": stream,
        }
        if tools:
            payload["tools"] = [t.to_openai_schema() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        headers.update(self.config.extra_headers)
        return headers

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code == 429:
            raise RateLimitError(f"Rate limit exceeded: {response.text}")
        if response.status_code >= 400:
            raise LLMError(f"LLM request failed ({response.status_code}): {response.text}")

    async def _araise_for_status(self, response: httpx.Response) -> None:
        if response.status_code == 429:
            raise RateLimitError(f"Rate limit exceeded: {await response.aread()}")
        if response.status_code >= 400:
            body = await response.aread()
            raise LLMError(f"LLM request failed ({response.status_code}): {body.decode()}")


class MockLLMClient(LLMClient):
    """Deterministic mock client for testing without API keys."""

    def __init__(self, config: DevAIConfig | None = None, responses: list[str] | None = None) -> None:
        super().__init__(config or DevAIConfig.mock())
        self._responses = list(responses or [])
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
        if tools and self._should_call_tool(messages):
            tool = tools[0]
            return Message.assistant(
                content=None,
                tool_calls=[
                    ToolCall(
                        id="call_mock_1",
                        name=tool.name,
                        arguments=_mock_tool_args(tool),
                    )
                ],
            )
        text = self._next_response(messages, json_mode=json_mode)
        return Message.assistant(text)

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

    def stream(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        response = self.complete(messages, tools=tools, temperature=temperature, max_tokens=max_tokens)
        content = response.content or ""
        for word in content.split(" "):
            yield word + " "

    async def astream(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDefinition] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        for chunk in self.stream(messages, tools=tools, temperature=temperature, max_tokens=max_tokens):
            yield chunk

    def _next_response(self, messages: list[Message], *, json_mode: bool) -> str:
        if self._responses:
            text = self._responses[self._call_count % len(self._responses)]
            self._call_count += 1
            return text
        last = messages[-1].content or ""
        if json_mode:
            return json.dumps({"summary": "mock response", "input_preview": last[:80]})
        if "review" in last.lower():
            return "Code review: looks good. Consider adding type hints and docstrings."
        if "debug" in last.lower() or "error" in last.lower():
            return "Debug suggestion: check for null values and add error handling."
        if "security" in last.lower():
            return "Security review: no critical issues found. Validate all user inputs."
        if "refactor" in last.lower():
            return "Refactoring suggestion: extract helper functions and reduce nesting."
        if "test" in last.lower():
            return "def test_example():\n    assert True"
        if "commit" in last.lower():
            return "feat: add new feature"
        if "explain" in last.lower():
            return "This code defines a function that processes input data."
        return f"Mock response for: {last[:100]}"

    def _should_call_tool(self, messages: list[Message]) -> bool:
        last = (messages[-1].content or "").lower()
        return "search" in last or "find" in last or "list" in last


class EmbeddingClient:
    """OpenAI-compatible embedding client."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig.from_env()

    def embed(self, texts: list[str]) -> list[list[float]]:
        if self.config.api_key == "mock-key":
            return [_mock_embedding(t) for t in texts]
        with httpx.Client(timeout=self.config.timeout) as client:
            response = client.post(
                f"{self.config.base_url.rstrip('/')}/embeddings",
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                json={"model": self.config.embedding_model, "input": texts},
            )
            if response.status_code >= 400:
                raise LLMError(f"Embedding request failed: {response.text}")
            data = response.json()
            return [item["embedding"] for item in data["data"]]

    async def aembed(self, texts: list[str]) -> list[list[float]]:
        if self.config.api_key == "mock-key":
            return [_mock_embedding(t) for t in texts]
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(
                f"{self.config.base_url.rstrip('/')}/embeddings",
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                json={"model": self.config.embedding_model, "input": texts},
            )
            if response.status_code >= 400:
                raise LLMError(f"Embedding request failed: {await response.aread()}")
            data = response.json()
            return [item["embedding"] for item in data["data"]]


def _parse_response(data: dict[str, Any]) -> Message:
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


def _parse_stream_line(line: str) -> str | None:
    if not line.startswith("data: "):
        return None
    payload = line[6:]
    if payload.strip() == "[DONE]":
        return None
    data = json.loads(payload)
    delta = data["choices"][0].get("delta", {})
    return delta.get("content")


def _mock_tool_args(tool: ToolDefinition) -> dict[str, Any]:
    """Generate plausible mock arguments for a tool call."""
    defaults: dict[str, dict[str, Any]] = {
        "read_file": {"path": "README.md"},
        "search_code": {"directory": ".", "pattern": "TODO"},
        "list_files": {"directory": ".", "pattern": "*.py"},
        "explain_code": {"code": "def foo(): pass"},
        "lint_python": {"code": "def foo(): pass"},
        "git_diff": {"staged": False},
        "count_complexity": {"code": "def foo(): return 1"},
    }
    return defaults.get(tool.name, {"query": "mock"})


def _mock_embedding(text: str, dims: int = 64) -> list[float]:
    import hashlib

    seed = int(hashlib.md5(text.encode()).hexdigest(), 16)
    return [((seed >> (i % 32)) % 1000) / 1000.0 for i in range(dims)]
