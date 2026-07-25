"""Retry utilities with exponential backoff."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

T = TypeVar("T")


def retry_sync(
    fn: Callable[..., T],
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    retryable: Callable[[Exception], bool] | None = None,
    **kwargs: Any,
) -> T:
    """Call fn with retries on transient failures."""
    retryable = retryable or _is_retryable
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt >= max_retries or not retryable(exc):
                raise
            delay = min(base_delay * (2 ** attempt), max_delay)
            time.sleep(delay)

    raise last_exc  # type: ignore[misc]


async def retry_async(
    fn: Callable[..., Coroutine[Any, Any, T]],
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    retryable: Callable[[Exception], bool] | None = None,
    **kwargs: Any,
) -> T:
    """Async variant of retry_sync."""
    retryable = retryable or _is_retryable
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            return await fn(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt >= max_retries or not retryable(exc):
                raise
            delay = min(base_delay * (2 ** attempt), max_delay)
            await asyncio.sleep(delay)

    raise last_exc  # type: ignore[misc]


def _is_retryable(exc: Exception) -> bool:
    from devai.exceptions import ProviderError

    if isinstance(exc, ProviderError) and exc.status_code is not None:
        return exc.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, (TimeoutError, ConnectionError, OSError))
