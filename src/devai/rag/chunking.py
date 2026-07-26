"""Text chunking utilities for RAG."""

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

    if len(text) <= chunk_size:
        return [text]

    chunks: list[str] = []
    paragraphs = text.split(separator)
    current = ""

    for para in paragraphs:
        if len(current) + len(para) + len(separator) <= chunk_size:
            current = f"{current}{separator}{para}" if current else para
        else:
            if current:
                chunks.append(current)
            if len(para) > chunk_size:
                for i in range(0, len(para), chunk_size - overlap):
                    chunks.append(para[i : i + chunk_size])
                current = ""
            else:
                current = para

    if current:
        chunks.append(current)

    if overlap > 0 and len(chunks) > 1:
        overlapped: list[str] = [chunks[0]]
        for i in range(1, len(chunks)):
            prev_tail = chunks[i - 1][-overlap:]
            overlapped.append(prev_tail + chunks[i])
        return overlapped

    return chunks
