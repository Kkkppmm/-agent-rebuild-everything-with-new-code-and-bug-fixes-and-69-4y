"""Rate limiting for LLM API calls."""

from __future__ import annotations

import threading
import time
from collections.abc import AsyncIterator, Iterator
from typing import Any

from devai.core.exceptions import RateLimitError
from devai.core.models import Message, Tool


class RateLimiter:
    """Token-bucket rate limiter for controlling API call throughput.

    Use ``RateLimiter`` to avoid hitting provider rate limits when running
    batch jobs, agents, or parallel workflows.
    """

    def __init__(self, *, requests_per_minute: float = 60.0, burst: int | None = None) -> None:
        if requests_per_minute <= 0:
            raise ValueError("requests_per_minute must be positive")
        self.rate = requests_per_minute / 60.0
        self.capacity = float(burst if burst is not None else max(1, int(requests_per_minute / 10)))
        self._tokens = self.capacity
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def acquire(self, *, timeout: float | None = None) -> None:
        """Block until a request token is available."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            if deadline is not None and time.monotonic() >= deadline:
                raise RateLimitError("Rate limit timeout exceeded")
            time.sleep(0.01)

    @property
    def available_tokens(self) -> float:
        """Current number of available tokens (approximate)."""
        with self._lock:
            self._refill()
            return self._tokens


class RateLimitedLLMClient:
    """LLM client wrapper that enforces rate limits before each call."""

    def __init__(
        self,
        client: Any,
        limiter: RateLimiter | None = None,
        *,
        requests_per_minute: float = 60.0,
    ) -> None:
        self.client = client
        self.limiter = limiter or RateLimiter(requests_per_minute=requests_per_minute)

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self.limiter.acquire()
        return self.client.complete(
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
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        self.limiter.acquire()
        yield from self.client.stream(
            messages, temperature=temperature, max_tokens=max_tokens
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
        self.limiter.acquire()
        return await self.client.acomplete(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        self.limiter.acquire()
        async for chunk in self.client.astream(
            messages, temperature=temperature, max_tokens=max_tokens
        ):
            yield chunk
