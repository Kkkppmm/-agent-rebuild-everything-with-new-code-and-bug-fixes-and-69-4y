"""Retry utilities for API calls."""

import time
from typing import Callable, TypeVar

T = TypeVar("T")


def with_retry(
    fn: Callable[[], T],
    max_retries: int = 3,
    delay: float = 1.0,
    on_retry: Callable[[Exception, int], None] | None = None,
) -> T:
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if attempt >= max_retries:
                break
            if on_retry:
                on_retry(exc, attempt + 1)
            time.sleep(delay * (2 ** attempt))
    raise last_exc  # type: ignore[misc]
