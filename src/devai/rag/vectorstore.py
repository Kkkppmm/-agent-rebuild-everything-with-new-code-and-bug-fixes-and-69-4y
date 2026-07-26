"""Simple in-memory vector store for RAG."""

from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass
class Document:
    content: str
    metadata: dict = field(default_factory=dict)
    embedding: list[float] | None = None


class VectorStore:
    """In-memory vector store with cosine similarity search."""

    def __init__(self) -> None:
        self.documents: list[Document] = []

    def add(self, content: str, metadata: dict | None = None) -> None:
        self.documents.append(Document(content=content, metadata=metadata or {}))

    def add_with_embeddings(
        self,
        contents: list[str],
        embeddings: list[list[float]],
        metadata: list[dict] | None = None,
    ) -> None:
        meta_list = metadata or [{}] * len(contents)
        for content, emb, meta in zip(contents, embeddings, meta_list):
            self.documents.append(
                Document(content=content, metadata=meta, embedding=emb)
            )

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def search(self, query_embedding: list[float], top_k: int = 3) -> list[Document]:
        scored = []
        for doc in self.documents:
            if doc.embedding is None:
                continue
            score = self._cosine_similarity(query_embedding, doc.embedding)
            scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored[:top_k]]

    def __len__(self) -> int:
        return len(self.documents)

    def clear(self) -> None:
        self.documents = []
