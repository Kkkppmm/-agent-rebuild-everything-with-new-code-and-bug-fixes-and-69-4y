"""Retry utilities for API calls."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

from devai.core.exceptions import RateLimitError

T = TypeVar("T")


def with_retries(
    fn: Callable[[], T],
    *,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    retryable: tuple[type[Exception], ...] = (RateLimitError,),
) -> T:
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except retryable as exc:
            last_exc = exc
            if attempt < max_retries:
                time.sleep(retry_delay * (2**attempt))
    raise last_exc  # type: ignore[misc]


async def async_with_retries(
    fn: Callable[[], Awaitable[T]],
    *,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    retryable: tuple[type[Exception], ...] = (RateLimitError,),
) -> T:
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await fn()
        except retryable as exc:
            last_exc = exc
            if attempt < max_retries:
                await asyncio.sleep(retry_delay * (2**attempt))
    raise last_exc  # type: ignore[misc]
