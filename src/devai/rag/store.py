"""In-memory vector store for retrieval-augmented generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from devai.core.embeddings import EmbeddingClientProtocol, MockEmbeddingClient, cosine_similarity


@dataclass
class Document:
    """A stored text chunk with optional metadata."""

    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    score: float | None = None


class VectorStore:
    """Simple in-memory vector store backed by an embedding client."""

    def __init__(self, embedder: EmbeddingClientProtocol | None = None):
        self.embedder = embedder or MockEmbeddingClient()
        self._documents: list[Document] = []
        self._vectors: list[list[float]] = []

    def __len__(self) -> int:
        return len(self._documents)

    async def add(
        self,
        texts: list[str],
        metadata: list[dict[str, Any]] | None = None,
    ) -> int:
        """Embed and store text chunks. Returns number of documents added."""
        if not texts:
            return 0
        meta = metadata or [{} for _ in texts]
        if len(meta) != len(texts):
            raise ValueError("metadata length must match texts length")

        vectors = await self.embedder.embed(texts)
        for text, item_meta, vector in zip(texts, meta, vectors):
            self._documents.append(Document(content=text, metadata=item_meta))
            self._vectors.append(vector)
        return len(texts)

    def add_sync(
        self,
        texts: list[str],
        metadata: list[dict[str, Any]] | None = None,
    ) -> int:
        import asyncio

        return asyncio.run(self.add(texts, metadata=metadata))

    async def search(self, query: str, *, top_k: int = 5) -> list[Document]:
        """Return the top-k most similar documents for a query."""
        if not self._documents:
            return []

        query_vector = (await self.embedder.embed([query]))[0]
        scored = [
            (cosine_similarity(query_vector, vector), doc)
            for vector, doc in zip(self._vectors, self._documents)
        ]
        scored.sort(key=lambda item: item[0], reverse=True)
        results: list[Document] = []
        for score, doc in scored[:top_k]:
            results.append(
                Document(content=doc.content, metadata=dict(doc.metadata), score=score)
            )
        return results

    def search_sync(self, query: str, *, top_k: int = 5) -> list[Document]:
        import asyncio

        return asyncio.run(self.search(query, top_k=top_k))

    def clear(self) -> None:
        self._documents.clear()
        self._vectors.clear()
