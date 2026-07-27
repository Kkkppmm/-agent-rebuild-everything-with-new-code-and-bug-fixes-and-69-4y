"""Text chunking for RAG."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Document:
    content: str
    metadata: dict[str, str]


def chunk_text(
    text: str,
    chunk_size: int = 500,
    overlap: int = 50,
    metadata: dict[str, str] | None = None,
) -> list[Document]:
    """Split text into overlapping chunks."""
    if not text.strip():
        return []

    meta = metadata or {}
    paragraphs = re.split(r"\n\s*\n", text.strip())
    chunks: list[Document] = []
    current = ""

    for para in paragraphs:
        if len(current) + len(para) + 1 <= chunk_size:
            current = f"{current}\n\n{para}".strip() if current else para
        else:
            if current:
                chunks.extend(_split_long(current, chunk_size, overlap, meta))
            current = para

    if current:
        chunks.extend(_split_long(current, chunk_size, overlap, meta))

    return chunks


def _split_long(
    text: str,
    chunk_size: int,
    overlap: int,
    metadata: dict[str, str],
) -> list[Document]:
    if len(text) <= chunk_size:
        return [Document(content=text, metadata=dict(metadata))]

    chunks: list[Document] = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(Document(content=chunk, metadata=dict(metadata)))
        start = end - overlap
        if start >= len(text):
            break
    return chunks
