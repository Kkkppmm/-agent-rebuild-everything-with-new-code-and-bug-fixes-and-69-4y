"""Streaming utilities for DevAI."""

from dataclasses import dataclass
from typing import AsyncIterator, Iterator


@dataclass
class StreamChunk:
    """A single chunk from a streaming response."""

    content: str
    done: bool = False


def collect_stream(stream: Iterator[StreamChunk]) -> str:
    """Collect all chunks from a sync stream into a single string."""
    parts: list[str] = []
    for chunk in stream:
        if chunk.content:
            parts.append(chunk.content)
    return "".join(parts)


async def collect_stream_async(stream: AsyncIterator[StreamChunk]) -> str:
    """Collect all chunks from an async stream into a single string."""
    parts: list[str] = []
    async for chunk in stream:
        if chunk.content:
            parts.append(chunk.content)
    return "".join(parts)
