"""Batch processing for LLM requests."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypeVar

from devai.core.client import LLMClientProtocol
from devai.core.models import Message

T = TypeVar("T")


class BatchRunner:
    """Run multiple LLM requests in parallel."""

    def __init__(self, client: LLMClientProtocol, max_workers: int = 4) -> None:
        self.client = client
        self.max_workers = max_workers

    def run(
        self,
        message_batches: list[list[Message]],
        *,
        json_mode: bool = False,
        temperature: float | None = None,
    ) -> list[str]:
        """Run multiple completions in parallel and return results in order."""
        results: list[str | None] = [None] * len(message_batches)

        def _complete(idx: int, messages: list[Message]) -> tuple[int, str]:
            return idx, self.client.complete(
                messages, json_mode=json_mode, temperature=temperature
            )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(_complete, i, msgs): i
                for i, msgs in enumerate(message_batches)
            }
            for future in as_completed(futures):
                idx, result = future.result()
                results[idx] = result

        return [r or "" for r in results]

    def map(
        self,
        items: list[T],
        fn: Callable[[T], list[Message]],
        *,
        json_mode: bool = False,
        temperature: float | None = None,
    ) -> list[str]:
        """Map items to message batches and run completions."""
        batches = [fn(item) for item in items]
        return self.run(batches, json_mode=json_mode, temperature=temperature)
