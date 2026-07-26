"""Simple in-memory vector store for RAG."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from devai.rag.chunking import TextChunk


@dataclass
class Document:
    content: str
    embedding: list[float]
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class SearchResult:
    document: Document
    score: float


class VectorStore:
    """In-memory vector store with cosine similarity search."""

    def __init__(self) -> None:
        self._documents: list[Document] = []

    def add(self, content: str, embedding: list[float], metadata: dict[str, str] | None = None) -> None:
        self._documents.append(Document(content=content, embedding=embedding, metadata=metadata or {}))

    def add_chunks(self, chunks: list[TextChunk], embeddings: list[list[float]]) -> None:
        if len(chunks) != len(embeddings):
            raise ValueError("chunks and embeddings must have the same length")
        for chunk, embedding in zip(chunks, embeddings):
            self.add(chunk.content, embedding, chunk.metadata)

    def search(self, query_embedding: list[float], top_k: int = 5) -> list[SearchResult]:
        scored = [
            SearchResult(document=doc, score=_cosine_similarity(query_embedding, doc.embedding))
            for doc in self._documents
        ]
        scored.sort(key=lambda r: r.score, reverse=True)
        return scored[:top_k]

    def __len__(self) -> int:
        return len(self._documents)

    def clear(self) -> None:
        self._documents.clear()


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
