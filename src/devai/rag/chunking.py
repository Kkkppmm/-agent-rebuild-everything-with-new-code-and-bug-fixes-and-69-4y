"""Text chunking utilities for RAG pipelines."""

from __future__ import annotations


def chunk_text(
    text: str,
    *,
    chunk_size: int = 500,
    overlap: int = 50,
    separator: str = "\n",
) -> list[str]:
    """Split text into overlapping chunks."""
    if not text.strip():
        return []

    if separator and separator in text:
        parts = text.split(separator)
        chunks: list[str] = []
        current = ""
        for part in parts:
            candidate = (current + separator + part).strip() if current else part
            if len(candidate) <= chunk_size:
                current = candidate
            else:
                if current:
                    chunks.append(current)
                current = part
        if current:
            chunks.append(current)
        return _apply_overlap(chunks, overlap)

    # Character-based chunking fallback
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start = end - overlap
    return chunks


def _apply_overlap(chunks: list[str], overlap: int) -> list[str]:
    if overlap <= 0 or len(chunks) <= 1:
        return chunks
    result = [chunks[0]]
    for i in range(1, len(chunks)):
        prev_tail = chunks[i - 1][-overlap:] if len(chunks[i - 1]) > overlap else chunks[i - 1]
        result.append(prev_tail + chunks[i])
    return result
