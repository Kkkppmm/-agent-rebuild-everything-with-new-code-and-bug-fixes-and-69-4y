"""Retry utilities for DevAI."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


def with_retries(
    func: Callable[[], T],
    max_retries: int = 3,
    delay: float = 1.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> T:
    """Execute a function with exponential backoff retries."""
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return func()
        except exceptions as exc:
            last_exc = exc
            if attempt < max_retries:
                time.sleep(delay * (2**attempt))
    raise last_exc  # type: ignore[misc]


async def async_with_retries(
    func: Callable[[], Awaitable[T]],
    max_retries: int = 3,
    delay: float = 1.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> T:
    """Execute an async function with exponential backoff retries."""
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await func()
        except exceptions as exc:
            last_exc = exc
            if attempt < max_retries:
                await asyncio.sleep(delay * (2**attempt))
    raise last_exc  # type: ignore[misc]
