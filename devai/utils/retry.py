"""Retry helpers for resilient API calls."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


def retry_sync(
  func: Callable[[], T],
  *,
  max_attempts: int = 3,
  base_delay: float = 0.5,
) -> T:
  """Retry a synchronous callable with exponential backoff."""
  last_error: Exception | None = None
  for attempt in range(1, max_attempts + 1):
    try:
      return func()
    except Exception as exc:  # noqa: BLE001 - retry boundary
      last_error = exc
      if attempt == max_attempts:
        break
      time.sleep(base_delay * (2 ** (attempt - 1)))
  assert last_error is not None
  raise last_error


async def retry_async(
  func: Callable[[], Awaitable[T]],
  *,
  max_attempts: int = 3,
  base_delay: float = 0.5,
) -> T:
  """Retry an async callable with exponential backoff."""
  last_error: Exception | None = None
  for attempt in range(1, max_attempts + 1):
    try:
      return await func()
    except Exception as exc:  # noqa: BLE001 - retry boundary
      last_error = exc
      if attempt == max_attempts:
        break
      await asyncio.sleep(base_delay * (2 ** (attempt - 1)))
  assert last_error is not None
  raise last_error
