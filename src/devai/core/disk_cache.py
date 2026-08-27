"""Disk-backed LLM response cache for development workflows."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

from devai.core.models import Message, Tool


class DiskCachedLLMClient:
    """LLM client wrapper that persists responses to disk by message hash.

    Useful during development to avoid repeated API calls for identical prompts.
  Cache entries are stored as JSON files under ``cache_dir``.
    """

    def __init__(
        self,
        client: Any,
        cache_dir: str | Path = ".devai-cache",
        *,
        max_entries: int | None = None,
    ) -> None:
        self.client = client
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_entries = max_entries

    def _cache_key(
        self,
        messages: list[Message],
        **kwargs: Any,
    ) -> str:
        parts = [json.dumps(m.to_dict(), sort_keys=True) for m in messages]
        parts.append(json.dumps(kwargs, sort_keys=True, default=str))
        digest = hashlib.sha256("|".join(parts).encode()).hexdigest()
        return digest

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def _read(self, key: str) -> str | None:
        path = self._cache_path(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data["response"]
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    def _write(self, key: str, response: str) -> None:
        if self.max_entries is not None:
            entries = sorted(self.cache_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
            while len(entries) >= self.max_entries:
                oldest = entries.pop(0)
                oldest.unlink(missing_ok=True)
        path = self._cache_path(key)
        path.write_text(
            json.dumps({"response": response}, ensure_ascii=False),
            encoding="utf-8",
        )

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        key = self._cache_key(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        cached = self._read(key)
        if cached is not None:
            return cached
        response = self.client.complete(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self._write(key, response)
        return response

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        return self.client.stream(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        key = self._cache_key(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        cached = self._read(key)
        if cached is not None:
            return cached
        response = await self.client.acomplete(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self._write(key, response)
        return response

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        async for chunk in self.client.astream(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
        ):
            yield chunk

    def clear_cache(self) -> None:
        for path in self.cache_dir.glob("*.json"):
            path.unlink(missing_ok=True)

    @property
    def cache_size(self) -> int:
        return len(list(self.cache_dir.glob("*.json")))
