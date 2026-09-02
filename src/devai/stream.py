"""Streaming utilities for collecting and observing LLM output."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from devai.core.client import LLMClientProtocol
from devai.core.models import Message


@dataclass
class StreamResult:
    """Collected output from a streaming LLM call."""

    text: str
    chunk_count: int = 0
    elapsed_ms: float = 0.0
    chunks: list[str] = field(default_factory=list)

    @property
    def tokens_approx(self) -> int:
        """Rough token estimate (words * 1.3)."""
        return int(len(self.text.split()) * 1.3)


class StreamCollector:
    """Collect streaming LLM chunks into a single result with optional callbacks."""

    @staticmethod
    def collect(
        stream: Iterator[str],
        *,
        on_chunk: Callable[[str], None] | None = None,
        store_chunks: bool = False,
    ) -> StreamResult:
        """Collect all chunks from a sync stream iterator."""
        start = time.perf_counter()
        parts: list[str] = []
        stored: list[str] = []
        count = 0
        for chunk in stream:
            parts.append(chunk)
            count += 1
            if store_chunks:
                stored.append(chunk)
            if on_chunk is not None:
                on_chunk(chunk)
        elapsed = (time.perf_counter() - start) * 1000
        return StreamResult(
            text="".join(parts),
            chunk_count=count,
            elapsed_ms=elapsed,
            chunks=stored,
        )

    @staticmethod
    async def acollect(
        stream: AsyncIterator[str],
        *,
        on_chunk: Callable[[str], None] | None = None,
        store_chunks: bool = False,
    ) -> StreamResult:
        """Collect all chunks from an async stream iterator."""
        start = time.perf_counter()
        parts: list[str] = []
        stored: list[str] = []
        count = 0
        async for chunk in stream:
            parts.append(chunk)
            count += 1
            if store_chunks:
                stored.append(chunk)
            if on_chunk is not None:
                on_chunk(chunk)
        elapsed = (time.perf_counter() - start) * 1000
        return StreamResult(
            text="".join(parts),
            chunk_count=count,
            elapsed_ms=elapsed,
            chunks=stored,
        )

    @staticmethod
    def from_messages(
        client: LLMClientProtocol,
        messages: list[Message],
        *,
        on_chunk: Callable[[str], None] | None = None,
        store_chunks: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> StreamResult:
        """Stream and collect a completion for the given messages."""
        stream = client.stream(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return StreamCollector.collect(
            stream,
            on_chunk=on_chunk,
            store_chunks=store_chunks,
        )

    @staticmethod
    async def afrom_messages(
        client: LLMClientProtocol,
        messages: list[Message],
        *,
        on_chunk: Callable[[str], None] | None = None,
        store_chunks: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> StreamResult:
        """Async stream and collect a completion for the given messages."""
        stream = client.astream(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return await StreamCollector.acollect(
            stream,
            on_chunk=on_chunk,
            store_chunks=store_chunks,
        )

    @staticmethod
    def print_stream(
        stream: Iterator[str],
        *,
        end: str = "",
        flush: bool = True,
    ) -> StreamResult:
        """Collect a stream while printing each chunk to stdout."""
        import sys

        def _on_chunk(chunk: str) -> None:
            sys.stdout.write(chunk)
            if flush:
                sys.stdout.flush()

        result = StreamCollector.collect(stream, on_chunk=_on_chunk)
        if end:
            sys.stdout.write(end)
            if flush:
                sys.stdout.flush()
        return result
