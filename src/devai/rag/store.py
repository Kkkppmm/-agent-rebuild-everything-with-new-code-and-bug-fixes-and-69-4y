"""In-memory vector store for RAG."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Protocol


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


@dataclass
class Document:
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    embedding: list[float] | None = None


class VectorStore:
    """Simple in-memory vector store with cosine similarity search."""

    def __init__(self, embedder: Embedder | None = None) -> None:
        self.embedder = embedder
        self._documents: list[Document] = []

    def add(self, content: str, *, metadata: dict[str, Any] | None = None) -> None:
        doc = Document(content=content, metadata=metadata or {})
        if self.embedder:
            doc.embedding = self.embedder.embed([content])[0]
        self._documents.append(doc)

    def add_many(self, contents: list[str], *, metadatas: list[dict[str, Any]] | None = None) -> None:
        metadatas = metadatas or [{}] * len(contents)
        if self.embedder:
            embeddings = self.embedder.embed(contents)
            for content, meta, emb in zip(contents, metadatas, embeddings):
                self._documents.append(Document(content=content, metadata=meta, embedding=emb))
        else:
            for content, meta in zip(contents, metadatas):
                self._documents.append(Document(content=content, metadata=meta))

    def search(self, query: str, *, top_k: int = 3) -> list[Document]:
        if not self._documents:
            return []

        if self.embedder:
            query_emb = self.embedder.embed([query])[0]
            scored = [
                (self._cosine_similarity(query_emb, doc.embedding or []), doc)
                for doc in self._documents
                if doc.embedding
            ]
            scored.sort(key=lambda x: x[0], reverse=True)
            return [doc for _, doc in scored[:top_k]]

        # Keyword fallback
        query_lower = query.lower()
        scored = [
            (sum(1 for word in query_lower.split() if word in doc.content.lower()), doc)
            for doc in self._documents
        ]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in scored[:top_k] if score > 0]

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def __len__(self) -> int:
        return len(self._documents)

    def clear(self) -> None:
        self._documents.clear()
