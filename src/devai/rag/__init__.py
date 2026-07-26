"""Retrieval-augmented generation components."""

from __future__ import annotations

import math
from typing import Any

from devai.core.client import EmbeddingClient, LLMClient, MockLLMClient
from devai.core.models import Message, Role


def chunk_text(
    text: str,
    chunk_size: int = 500,
    overlap: int = 50,
    separator: str = "\n",
) -> list[str]:
    """Split text into overlapping chunks."""
    if len(text) <= chunk_size:
        return [text]

    chunks: list[str] = []
    paragraphs = text.split(separator)
    current = ""

    for para in paragraphs:
        if len(current) + len(para) + 1 <= chunk_size:
            current = f"{current}{separator}{para}" if current else para
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


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class VectorStore:
    """In-memory vector store for document retrieval."""

    def __init__(self, embedding_client: EmbeddingClient | None = None):
        self.embedding_client = embedding_client
        self._documents: list[str] = []
        self._embeddings: list[list[float]] = []
        self._metadata: list[dict[str, Any]] = []

    def add_documents(
        self,
        documents: list[str],
        embeddings: list[list[float]] | None = None,
        metadata: list[dict[str, Any]] | None = None,
    ) -> None:
        if embeddings is None and self.embedding_client:
            embeddings = self.embedding_client.embed(documents)
        elif embeddings is None:
            embeddings = [_simple_hash_embed(doc) for doc in documents]

        self._documents.extend(documents)
        self._embeddings.extend(embeddings)
        self._metadata.extend(metadata or [{} for _ in documents])

    def search(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        if not self._documents:
            return []

        if self.embedding_client:
            query_embedding = self.embedding_client.embed_one(query)
        else:
            query_embedding = _simple_hash_embed(query)

        scores = [
            cosine_similarity(query_embedding, emb)
            for emb in self._embeddings
        ]
        ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)[:top_k]

        return [
            {
                "document": self._documents[idx],
                "score": score,
                "metadata": self._metadata[idx],
            }
            for idx, score in ranked
        ]

    def __len__(self) -> int:
        return len(self._documents)


def _simple_hash_embed(text: str, dim: int = 128) -> list[float]:
    """Simple hash-based embedding for testing without an API."""
    vec = [0.0] * dim
    for i, word in enumerate(text.lower().split()):
        h = hash(word) % dim
        vec[h] += 1.0 / (i + 1)
    norm = math.sqrt(sum(v * v for v in vec))
    return [v / norm if norm > 0 else 0.0 for v in vec]


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        vector_store: VectorStore,
        top_k: int = 3,
        system_prompt: str = "Answer based on the provided context. If unsure, say so.",
    ):
        self.client = client
        self.vector_store = vector_store
        self.top_k = top_k
        self.system_prompt = system_prompt

    def query(self, question: str) -> str:
        results = self.vector_store.search(question, top_k=self.top_k)
        context = "\n\n---\n\n".join(r["document"] for r in results)

        messages = [
            Message(role=Role.SYSTEM, content=self.system_prompt),
            Message(
                role=Role.USER,
                content=f"Context:\n{context}\n\nQuestion: {question}",
            ),
        ]
        response = self.client.chat(messages)
        return response.content
