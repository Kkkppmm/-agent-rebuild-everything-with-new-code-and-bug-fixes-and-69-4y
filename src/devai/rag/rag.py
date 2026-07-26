"""RAG utilities: chunking, vector store, and retrieval chain."""

from __future__ import annotations

import math
from typing import Any

from devai.core.client import EmbeddingClient, LLMClient, MockLLMClient


def chunk_text(
    text: str,
    chunk_size: int = 500,
    overlap: int = 50,
    separator: str = "\n",
) -> list[str]:
    """Split text into overlapping chunks."""
    if not text:
        return []

    if len(text) <= chunk_size:
        return [text]

    chunks: list[str] = []
    paragraphs = text.split(separator)
    current = ""

    for para in paragraphs:
        if len(current) + len(para) + len(separator) <= chunk_size:
            current = current + separator + para if current else para
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

    # Add overlap between chunks
    if overlap > 0 and len(chunks) > 1:
        overlapped = [chunks[0]]
        for i in range(1, len(chunks)):
            prev_tail = chunks[i - 1][-overlap:]
            overlapped.append(prev_tail + chunks[i])
        return overlapped

    return chunks


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class VectorStore:
    """Simple in-memory vector store for RAG."""

    def __init__(self, embedding_client: EmbeddingClient | None = None):
        self._documents: list[str] = []
        self._embeddings: list[list[float]] = []
        self._metadata: list[dict[str, Any]] = []
        self._embedding_client = embedding_client

    def add(self, documents: list[str], metadata: list[dict[str, Any]] | None = None) -> None:
        self._documents.extend(documents)
        if metadata:
            self._metadata.extend(metadata)
        else:
            self._metadata.extend({} for _ in documents)

        if self._embedding_client:
            new_embeddings = self._embedding_client.embed(documents)
            self._embeddings.extend(new_embeddings)

    def add_with_embeddings(
        self,
        documents: list[str],
        embeddings: list[list[float]],
        metadata: list[dict[str, Any]] | None = None,
    ) -> None:
        self._documents.extend(documents)
        self._embeddings.extend(embeddings)
        self._metadata.extend(metadata or {} for _ in documents)

    def search(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        if not self._documents:
            return []

        if self._embedding_client and self._embeddings:
            query_emb = self._embedding_client.embed_one(query)
            scores = [_cosine_similarity(query_emb, emb) for emb in self._embeddings]
        else:
            # Fallback: simple keyword matching
            query_lower = query.lower()
            scores = [
                sum(1 for word in query_lower.split() if word in doc.lower()) / max(len(doc), 1)
                for doc in self._documents
            ]

        ranked = sorted(
            zip(scores, self._documents, self._metadata),
            key=lambda x: x[0],
            reverse=True,
        )

        return [
            {"score": score, "document": doc, "metadata": meta}
            for score, doc, meta in ranked[:top_k]
        ]

    def __len__(self) -> int:
        return len(self._documents)

    def clear(self) -> None:
        self._documents.clear()
        self._embeddings.clear()
        self._metadata.clear()


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        vector_store: VectorStore,
        top_k: int = 3,
    ):
        self.client = client
        self.vector_store = vector_store
        self.top_k = top_k

    def run(self, query: str) -> str:
        results = self.vector_store.search(query, top_k=self.top_k)
        context = "\n\n---\n\n".join(r["document"] for r in results)

        prompt = (
            f"Use the following context to answer the question. "
            f"If the context doesn't contain the answer, say so.\n\n"
            f"Context:\n{context}\n\n"
            f"Question: {query}"
        )

        response = self.client.chat([{"role": "user", "content": prompt}])
        return response.content or ""

    def add_documents(self, text: str, chunk_size: int = 500) -> int:
        chunks = chunk_text(text, chunk_size=chunk_size)
        self.vector_store.add(chunks)
        return len(chunks)
