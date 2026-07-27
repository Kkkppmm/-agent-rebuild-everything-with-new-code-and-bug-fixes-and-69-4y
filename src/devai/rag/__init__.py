"""Retrieval-augmented generation."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from devai.core.models import Message, Role


def chunk_text(
  text: str,
  chunk_size: int = 500,
  overlap: int = 50,
  separator: str = "\n\n",
) -> list[str]:
  """Split text into overlapping chunks."""
  if not text.strip():
    return []
  parts = text.split(separator) if separator else [text]
  chunks: list[str] = []
  current = ""
  for part in parts:
    if len(current) + len(part) + len(separator) <= chunk_size:
      current = f"{current}{separator}{part}" if current else part
    else:
      if current:
        chunks.append(current)
      if len(part) > chunk_size:
        for i in range(0, len(part), chunk_size - overlap):
          chunks.append(part[i:i + chunk_size])
        current = ""
      else:
        current = part
  if current:
    chunks.append(current)

  if overlap > 0 and len(chunks) > 1:
    overlapped = [chunks[0]]
    for i in range(1, len(chunks)):
      prev_tail = chunks[i - 1][-overlap:]
      overlapped.append(prev_tail + chunks[i])
    return overlapped
  return chunks


def _tokenize(text: str) -> set[str]:
  return set(re.findall(r"\w+", text.lower()))


def _similarity(a: str, b: str) -> float:
  tokens_a = _tokenize(a)
  tokens_b = _tokenize(b)
  if not tokens_a or not tokens_b:
    return 0.0
  intersection = tokens_a & tokens_b
  return len(intersection) / math.sqrt(len(tokens_a) * len(tokens_b))


@dataclass
class Document:
  content: str
  metadata: dict[str, Any] = field(default_factory=dict)


class VectorStore:
  """Simple in-memory document store with keyword similarity search."""

  def __init__(self) -> None:
    self._documents: list[Document] = []

  def add_documents(self, texts: list[str], metadata: list[dict] | None = None) -> None:
    meta = metadata or [{}] * len(texts)
    for text, m in zip(texts, meta):
      self._documents.append(Document(content=text, metadata=m))

  def add(self, content: str, **metadata: Any) -> None:
    self._documents.append(Document(content=content, metadata=metadata))

  def search(self, query: str, top_k: int = 3) -> list[Document]:
    scored = [(doc, _similarity(query, doc.content)) for doc in self._documents]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [doc for doc, score in scored[:top_k] if score > 0]

  def __len__(self) -> int:
    return len(self._documents)


class LLMProtocol(Protocol):
  def complete(self, messages: list[Message], **kwargs: Any) -> Any: ...


class RAGChain:
  """Retrieval-augmented generation chain."""

  def __init__(
    self,
    client: LLMProtocol,
    store: VectorStore,
    top_k: int = 3,
    system_prompt: str = "Answer based on the provided context. If unsure, say so.",
  ) -> None:
    self.client = client
    self.store = store
    self.top_k = top_k
    self.system_prompt = system_prompt

  def query(self, question: str, **kwargs: Any) -> str:
    docs = self.store.search(question, top_k=self.top_k)
    context = "\n\n---\n\n".join(d.content for d in docs) or "(no relevant context found)"
    messages = [
      Message(role=Role.SYSTEM, content=self.system_prompt),
      Message(role=Role.USER, content=f"Context:\n{context}\n\nQuestion: {question}"),
    ]
    result = self.client.complete(messages, **kwargs)
    return result.content if hasattr(result, "content") else str(result)
