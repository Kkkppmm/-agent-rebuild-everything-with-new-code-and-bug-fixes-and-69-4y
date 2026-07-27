"""RAG utilities — chunking, vector store, and retrieval chains."""

from __future__ import annotations

import math
from dataclasses import dataclass, field


def chunk_text(
  text: str,
  chunk_size: int = 500,
  overlap: int = 50,
  separator: str = "\n",
) -> list[str]:
  """Split text into overlapping chunks."""
  if len(text) <= chunk_size:
    return [text]
  parts = text.split(separator)
  chunks: list[str] = []
  current: list[str] = []
  current_len = 0
  for part in parts:
    part_len = len(part) + len(separator)
    if current_len + part_len > chunk_size and current:
      chunks.append(separator.join(current))
      overlap_text = separator.join(current)[-overlap:]
      current = [overlap_text, part] if overlap_text else [part]
      current_len = sum(len(p) + len(separator) for p in current)
    else:
      current.append(part)
      current_len += part_len
  if current:
    chunks.append(separator.join(current))
  return chunks


@dataclass
class Document:
  content: str
  metadata: dict = field(default_factory=dict)
  embedding: list[float] | None = None


def _cosine_similarity(a: list[float], b: list[float]) -> float:
  dot = sum(x * y for x, y in zip(a, b))
  norm_a = math.sqrt(sum(x * x for x in a))
  norm_b = math.sqrt(sum(x * x for x in b))
  if norm_a == 0 or norm_b == 0:
    return 0.0
  return dot / (norm_a * norm_b)


class VectorStore:
  """In-memory vector store with cosine similarity search."""

  def __init__(self) -> None:
    self.documents: list[Document] = []

  def add_documents(self, texts: list[str], metadata: list[dict] | None = None) -> None:
    meta = metadata or [{}] * len(texts)
    for text, m in zip(texts, meta):
      self.documents.append(Document(content=text, metadata=m))

  def add_embeddings(self, embeddings: list[list[float]]) -> None:
    for doc, emb in zip(self.documents, embeddings):
      doc.embedding = emb

  def search(self, query_embedding: list[float], top_k: int = 3) -> list[Document]:
    scored = [
      (doc, _cosine_similarity(query_embedding, doc.embedding or []))
      for doc in self.documents
      if doc.embedding is not None
    ]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [doc for doc, _ in scored[:top_k]]

  def search_text(self, query: str, top_k: int = 3) -> list[Document]:
    """Simple keyword search fallback when no embeddings are available."""
    query_lower = query.lower()
    scored = [
      (doc, sum(1 for word in query_lower.split() if word in doc.content.lower()))
      for doc in self.documents
    ]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [doc for doc, score in scored[:top_k] if score > 0]

  def __len__(self) -> int:
    return len(self.documents)
