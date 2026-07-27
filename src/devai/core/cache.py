"""Response caching for LLM clients."""

from __future__ import annotations

import hashlib
import json
from typing import Any, AsyncIterator, Iterator

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import LLMResponse, Message, ToolDefinition
from devai.core.streaming import StreamChunk


def _cache_key(
    prompt: str | list[Message],
    *,
    system: str | None = None,
    json_mode: bool = False,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> str:
    payload = {
        "prompt": prompt if isinstance(prompt, str) else [m.model_dump() for m in prompt],
        "system": system,
        "json_mode": json_mode,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


class CachedLLMClient:
    """Wrap an LLM client with an in-memory response cache."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        *,
        max_entries: int = 256,
    ) -> None:
        self.client = client
        self.max_entries = max_entries
        self._cache: dict[str, LLMResponse] = {}
        self.hits = 0
        self.misses = 0

    def _store(self, key: str, response: LLMResponse) -> None:
        if key not in self._cache and len(self._cache) >= self.max_entries:
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[key] = response

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
        if tools:
            return self.client.complete(
                prompt,
                system=system,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        key = _cache_key(
            prompt,
            system=system,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if key in self._cache:
            self.hits += 1
            return self._cache[key]

        self.misses += 1
        response = self.client.complete(
            prompt,
            system=system,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self._store(key, response)
        return response

    def stream(
        self,
        prompt: str | list[Message],
        *,
        system: str | None = None,
    ) -> Iterator[StreamChunk]:
        yield from self.client.stream(prompt, system=system)

    async def acomplete(
        self,
        prompt: str | list[Message],
        *,
        system: str | None = None,
        tools: list[ToolDefinition] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        if tools:
            return await self.client.acomplete(
                prompt,
                system=system,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        key = _cache_key(
            prompt,
            system=system,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if key in self._cache:
            self.hits += 1
            return self._cache[key]

        self.misses += 1
        response = await self.client.acomplete(
            prompt,
            system=system,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self._store(key, response)
        return response

    async def astream(
        self,
        prompt: str | list[Message],
        *,
        system: str | None = None,
    ) -> AsyncIterator[StreamChunk]:
        async for chunk in self.client.astream(prompt, system=system):
            yield chunk

    def clear(self) -> None:
        self._cache.clear()
        self.hits = 0
        self.misses = 0

    @property
    def stats(self) -> dict[str, Any]:
        total = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,
            "size": len(self._cache),
            "hit_rate": self.hits / total if total else 0.0,
        }
