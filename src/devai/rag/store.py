"""RAG (Retrieval-Augmented Generation) components."""

from __future__ import annotations

import math
from dataclasses import dataclass, field


def chunk_text(
    text: str,
    chunk_size: int = 500,
    overlap: int = 50,
) -> list[str]:
    """Split text into overlapping chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap >= chunk_size:
        raise ValueError("overlap must be less than chunk_size")

    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start = end - overlap
    return chunks


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


@dataclass
class Document:
    content: str
    metadata: dict = field(default_factory=dict)
    embedding: list[float] | None = None


class VectorStore:
    """In-memory vector store for document retrieval."""

    def __init__(self) -> None:
        self._documents: list[Document] = []

    def add(self, content: str, embedding: list[float], metadata: dict | None = None) -> None:
        self._documents.append(
            Document(content=content, embedding=embedding, metadata=metadata or {})
        )

    def add_many(
        self,
        contents: list[str],
        embeddings: list[list[float]],
        metadatas: list[dict] | None = None,
    ) -> None:
        metas = metadatas or [{}] * len(contents)
        for content, emb, meta in zip(contents, embeddings, metas):
            self.add(content, emb, meta)

    def search(self, query_embedding: list[float], top_k: int = 3) -> list[Document]:
        scored = []
        for doc in self._documents:
            if doc.embedding is None:
                continue
            score = cosine_similarity(query_embedding, doc.embedding)
            scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored[:top_k]]

    def __len__(self) -> int:
        return len(self._documents)

    def clear(self) -> None:
        self._documents.clear()
