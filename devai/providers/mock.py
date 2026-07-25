"""Mock provider for testing and local development without API keys."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import AsyncIterator, Iterator
from typing import Any

from devai.providers.base import BaseProvider
from devai.types import ChatResponse, Usage


class MockProvider(BaseProvider):
    """Deterministic mock provider — no network calls."""

    def __init__(self, default_response: str = "Mock response from DevAI."):
        self.default_response = default_response
        self._call_log: list[dict[str, Any]] = []

    @property
    def call_log(self) -> list[dict[str, Any]]:
        """History of chat calls for test assertions."""
        return list(self._call_log)

    def _record(self, messages: list[dict[str, Any]], model: str) -> None:
        self._call_log.append({"messages": messages, "model": model})

    def _last_user_message(self, messages: list[dict[str, Any]]) -> str:
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                return content if isinstance(content, str) else str(content)
        return ""

    def _generate_response(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None
    ) -> ChatResponse:
        user_text = self._last_user_message(messages)
        content = self.default_response

        has_tool_results = any(msg.get("role") == "tool" for msg in messages)
        if has_tool_results:
            last_tool = next(
                (msg.get("content", "") for msg in reversed(messages) if msg.get("role") == "tool"),
                "",
            )
            return ChatResponse(
                content=f"Based on the tool result: {last_tool}",
                model="mock-devai",
                usage=Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            )

        if user_text.lower().startswith("echo:"):
            content = user_text[5:].strip()
        elif user_text.lower().startswith("json:"):
            content = json.dumps({"parsed": user_text[5:].strip()})
        elif "calculate" in user_text.lower() and re.search(r"\d+\s*[\+\-\*\/]\s*\d+", user_text):
            match = re.search(r"(\d+)\s*([\+\-\*\/])\s*(\d+)", user_text)
            if match:
                a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
                ops = {"+": a + b, "-": a - b, "*": a * b, "/": a / b if b else 0}
                content = str(ops.get(op, 0))

        tool_calls: list[dict[str, Any]] = []
        if tools and "weather" in user_text.lower():
            tool_calls = [
                {
                    "id": "call_mock_1",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": json.dumps({"city": "San Francisco"}),
                    },
                }
            ]
            content = ""

        usage = Usage(
            prompt_tokens=max(1, len(user_text) // 4),
            completion_tokens=max(1, len(content) // 4),
            total_tokens=max(2, (len(user_text) + len(content)) // 4),
        )
        return ChatResponse(content=content, model="mock-devai", usage=usage, tool_calls=tool_calls)

    def chat(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> ChatResponse:
        self._record(messages, model)
        return self._generate_response(messages, tools)

    async def chat_async(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> ChatResponse:
        self._record(messages, model)
        return self._generate_response(messages, tools)

    def chat_stream(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        self._record(messages, model)
        response = self._generate_response(messages, None)
        for char in response.content:
            yield char

    async def chat_stream_async(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        for token in self.chat_stream(messages, model, temperature, max_tokens, **kwargs):
            yield token

    def embed(self, texts: list[str], model: str, **kwargs: Any) -> list[list[float]]:
        vectors = []
        for text in texts:
            digest = hashlib.sha256(text.encode()).digest()
            vectors.append([b / 255.0 for b in digest[:32]])
        return vectors

    async def embed_async(
        self, texts: list[str], model: str, **kwargs: Any
    ) -> list[list[float]]:
        return self.embed(texts, model, **kwargs)
