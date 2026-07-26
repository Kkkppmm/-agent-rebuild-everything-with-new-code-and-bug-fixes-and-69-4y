"""Text chunking utilities for RAG."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TextChunk:
    content: str
    index: int
    metadata: dict[str, str] | None = None


def chunk_text(
    text: str,
    chunk_size: int = 500,
    overlap: int = 50,
    separator: str = "\n",
) -> list[TextChunk]:
    """Split text into overlapping chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap >= chunk_size:
        overlap = max(0, chunk_size // 5)

    paragraphs = text.split(separator)
    chunks: list[TextChunk] = []
    current = ""
    idx = 0

    for para in paragraphs:
        candidate = f"{current}{separator}{para}".strip() if current else para
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            if current:
                chunks.append(TextChunk(content=current, index=idx))
                idx += 1
                if overlap > 0 and len(current) > overlap:
                    current = current[-overlap:] + separator + para
                else:
                    current = para
            else:
                for i in range(0, len(para), chunk_size - overlap):
                    piece = para[i : i + chunk_size]
                    chunks.append(TextChunk(content=piece, index=idx))
                    idx += 1
                current = ""

    if current:
        chunks.append(TextChunk(content=current, index=idx))

    return chunks
