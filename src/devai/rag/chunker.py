"""Text chunking utilities for RAG pipelines."""

from __future__ import annotations


def chunk_text(
    text: str,
    *,
    chunk_size: int = 800,
    overlap: int = 100,
    separator: str = "\n",
) -> list[str]:
    """Split text into overlapping chunks suitable for embedding.

  Args:
      text: Source text to split.
      chunk_size: Target maximum characters per chunk.
      overlap: Characters shared between consecutive chunks.
      separator: Prefer splitting on this delimiter when possible.
  """
    text = text.strip()
    if not text:
        return []
    if len(text) <= chunk_size:
        return [text]

    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        if end < len(text):
            split_at = text.rfind(separator, start, end)
            if split_at > start + chunk_size // 2:
                end = split_at + len(separator)
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


def chunk_file(
    path: str,
    *,
    chunk_size: int = 800,
    overlap: int = 100,
) -> list[str]:
    """Read a file and return text chunks."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return chunk_text(handle.read(), chunk_size=chunk_size, overlap=overlap)
