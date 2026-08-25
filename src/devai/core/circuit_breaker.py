"""Circuit breaker for resilient LLM calls."""

from __future__ import annotations

import threading
import time
from collections.abc import AsyncIterator, Iterator
from enum import Enum
from typing import Any

from devai.core.exceptions import CircuitBreakerError
from devai.core.models import Message, Tool


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Prevent cascading failures when an LLM provider is down.

    The breaker opens after ``failure_threshold`` consecutive failures and
    transitions to half-open after ``recovery_timeout`` seconds.
    """

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._maybe_recover()
            return self._state

    def _maybe_recover(self) -> None:
        if self._state == CircuitState.OPEN and self._opened_at is not None:
            if time.monotonic() - self._opened_at >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN

    def before_call(self) -> None:
        with self._lock:
            self._maybe_recover()
            if self._state == CircuitState.OPEN:
                raise CircuitBreakerError("Circuit breaker is open")

    def record_success(self) -> None:
        with self._lock:
            self._failure_count = 0
            self._state = CircuitState.CLOSED
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()

    def reset(self) -> None:
        """Manually reset the breaker to closed state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._opened_at = None


class CircuitBreakerLLMClient:
    """LLM client wrapper with circuit breaker protection."""

    def __init__(self, client: Any, breaker: CircuitBreaker | None = None) -> None:
        self.client = client
        self.breaker = breaker or CircuitBreaker()

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self.breaker.before_call()
        try:
            response = self.client.complete(
                messages,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            self.breaker.record_success()
            return response
        except Exception:
            self.breaker.record_failure()
            raise

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        self.breaker.before_call()
        try:
            for chunk in self.client.stream(
                messages, temperature=temperature, max_tokens=max_tokens
            ):
                yield chunk
            self.breaker.record_success()
        except Exception:
            self.breaker.record_failure()
            raise

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self.breaker.before_call()
        try:
            response = await self.client.acomplete(
                messages,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            self.breaker.record_success()
            return response
        except Exception:
            self.breaker.record_failure()
            raise

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        self.breaker.before_call()
        try:
            async for chunk in self.client.astream(
                messages, temperature=temperature, max_tokens=max_tokens
            ):
                yield chunk
            self.breaker.record_success()
        except Exception:
            self.breaker.record_failure()
            raise
