"""LLM and embedding clients."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError, RateLimitError
from devai.core.models import Message, Role, Tool, ToolCall
from devai.core.retry import with_retries


class LLMClient:
    """OpenAI-compatible HTTP LLM client."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig()
        self._client = httpx.Client(
            base_url=self.config.base_url.rstrip("/"),
            headers=self._headers(),
            timeout=self.config.timeout,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def chat(
        self,
        prompt: str,
        *,
        system: str | None = None,
        messages: list[Message] | None = None,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Send a chat completion request and return the assistant text."""
        payload = self._build_payload(
            prompt=prompt,
            system=system,
            messages=messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=False,
        )

        def _request() -> str:
            response = self._client.post("/chat/completions", json=payload)
            if response.status_code == 429:
                raise RateLimitError("Rate limit exceeded")
            if response.status_code >= 400:
                raise LLMError(f"LLM request failed ({response.status_code}): {response.text}")
            data = response.json()
            return data["choices"][0]["message"]["content"]

        return with_retries(
            _request,
            max_retries=self.config.max_retries,
            retry_delay=self.config.retry_delay,
        )

    def chat_with_tools(
        self,
        messages: list[Message],
        tools: list[Tool],
        *,
        system: str | None = None,
    ) -> tuple[str | None, list[ToolCall]]:
        """Send a chat request with tools and return assistant text plus tool calls."""
        payload = self._build_payload(
            prompt="",
            system=system,
            messages=messages,
            tools=tools,
            stream=False,
        )
        payload.pop("messages")
        payload["messages"] = [m.to_dict() for m in self._prepare_messages("", system, messages)]

        response = self._client.post("/chat/completions", json=payload)
        if response.status_code >= 400:
            raise LLMError(f"LLM request failed ({response.status_code}): {response.text}")

        message = response.json()["choices"][0]["message"]
        content = message.get("content")
        tool_calls: list[ToolCall] = []
        for raw in message.get("tool_calls") or []:
            fn = raw.get("function", {})
            args = fn.get("arguments", "{}")
            if isinstance(args, str):
                args = json.loads(args)
            tool_calls.append(
                ToolCall(
                    id=raw.get("id", str(uuid.uuid4())),
                    name=fn.get("name", ""),
                    arguments=args,
                )
            )
        return content, tool_calls

    def stream(
        self,
        prompt: str,
        *,
        system: str | None = None,
        messages: list[Message] | None = None,
    ) -> Iterator[str]:
        """Stream chat completion tokens."""
        payload = self._build_payload(
            prompt=prompt,
            system=system,
            messages=messages,
            stream=True,
        )

        with self._client.stream("POST", "/chat/completions", json=payload) as response:
            if response.status_code >= 400:
                raise LLMError(f"LLM stream failed ({response.status_code})")
            for line in response.iter_lines():
                if not line or not line.startswith("data: "):
                    continue
                chunk = line[6:]
                if chunk.strip() == "[DONE]":
                    break
                data = json.loads(chunk)
                delta = data["choices"][0].get("delta", {})
                token = delta.get("content")
                if token:
                    yield token

    def _build_payload(
        self,
        *,
        prompt: str,
        system: str | None,
        messages: list[Message] | None,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream: bool = False,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [m.to_dict() for m in self._prepare_messages(prompt, system, messages)],
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.config.max_tokens,
            "stream": stream,
        }
        if tools:
            payload["tools"] = [t.to_openai_schema() for t in tools]
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _prepare_messages(
        self,
        prompt: str,
        system: str | None,
        messages: list[Message] | None,
    ) -> list[Message]:
        if messages:
            return list(messages)
        result: list[Message] = []
        effective_system = system or self.config.system_prompt
        if effective_system:
            result.append(Message(role=Role.SYSTEM, content=effective_system))
        if prompt:
            result.append(Message(role=Role.USER, content=prompt))
        return result

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> LLMClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class MockLLMClient:
    """Deterministic LLM client for tests and offline development."""

    def __init__(
        self,
        responses: list[str] | None = None,
        tool_responses: list[tuple[str | None, list[ToolCall]]] | None = None,
    ) -> None:
        self.responses = list(responses or ["Mock response."])
        self.tool_responses = list(tool_responses or [])
        self._index = 0
        self._tool_index = 0
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        prompt: str,
        *,
        system: str | None = None,
        messages: list[Message] | None = None,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self.calls.append(
            {
                "prompt": prompt,
                "system": system,
                "messages": messages,
                "tools": tools,
                "json_mode": json_mode,
            }
        )
        response = self.responses[self._index % len(self.responses)]
        self._index += 1
        return response

    def chat_with_tools(
        self,
        messages: list[Message],
        tools: list[Tool],
        *,
        system: str | None = None,
    ) -> tuple[str | None, list[ToolCall]]:
        self.calls.append({"messages": messages, "tools": tools, "system": system})
        if self.tool_responses:
            content, tool_calls = self.tool_responses[self._tool_index % len(self.tool_responses)]
            self._tool_index += 1
            return content, tool_calls
        return self.chat("", messages=messages, tools=tools), []

    def stream(
        self,
        prompt: str,
        *,
        system: str | None = None,
        messages: list[Message] | None = None,
    ) -> Iterator[str]:
        text = self.chat(prompt, system=system, messages=messages)
        yield from text


class EmbeddingClient:
    """OpenAI-compatible embedding client."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig()
        self._client = httpx.Client(
            base_url=self.config.base_url.rstrip("/"),
            headers=self._headers(),
            timeout=self.config.timeout,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def embed(self, texts: list[str]) -> list[list[float]]:
        response = self._client.post(
            "/embeddings",
            json={"model": self.config.embedding_model, "input": texts},
        )
        if response.status_code >= 400:
            raise LLMError(f"Embedding request failed ({response.status_code}): {response.text}")
        data = response.json()["data"]
        return [item["embedding"] for item in sorted(data, key=lambda x: x["index"])]

    def close(self) -> None:
        self._client.close()
