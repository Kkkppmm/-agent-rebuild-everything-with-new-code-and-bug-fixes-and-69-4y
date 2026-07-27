"""Retrieval-augmented generation utilities."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message, Role


def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
    """Split text into overlapping chunks."""
    if not text:
        return []
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start = end - overlap
        if start >= len(text):
            break
    return chunks


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _simple_embed(text: str, dim: int = 64) -> list[float]:
    """Deterministic hash-based embedding for testing without API."""
    vec = [0.0] * dim
    for token in text.lower().split():
        h = hash(token) % dim
        vec[h] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


@dataclass
class Document:
    content: str
    embedding: list[float] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class VectorStore:
    """In-memory vector store for RAG."""

    def __init__(self) -> None:
        self._documents: list[Document] = []

    def add_documents(self, texts: list[str], metadata: list[dict] | None = None) -> None:
        meta = metadata or [{}] * len(texts)
        for text, m in zip(texts, meta):
            self._documents.append(Document(content=text, embedding=_simple_embed(text), metadata=m))

    def add(self, text: str, embedding: list[float] | None = None, metadata: dict | None = None) -> None:
        self._documents.append(
            Document(content=text, embedding=embedding or _simple_embed(text), metadata=metadata or {})
        )

    def search(self, query: str, top_k: int = 3) -> list[Document]:
        query_emb = _simple_embed(query)
        scored = [(doc, _cosine_similarity(query_emb, doc.embedding)) for doc in self._documents]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [doc for doc, _ in scored[:top_k]]

    @property
    def size(self) -> int:
        return len(self._documents)


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        store: VectorStore,
        top_k: int = 3,
    ) -> None:
        self.client = client
        self.store = store
        self.top_k = top_k

    def query(self, question: str) -> str:
        docs = self.store.search(question, top_k=self.top_k)
        context = "\n\n".join(doc.content for doc in docs)
        messages = [
            Message(
                role=Role.SYSTEM,
                content="Answer based on the provided context. If unsure, say so.",
            ),
            Message(
                role=Role.USER,
                content=f"Context:\n{context}\n\nQuestion: {question}",
            ),
        ]
        return self.client.complete(messages).content
