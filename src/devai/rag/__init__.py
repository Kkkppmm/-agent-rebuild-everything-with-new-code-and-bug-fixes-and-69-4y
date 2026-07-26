"""Retrieval-augmented generation components."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from devai.core.client import EmbeddingClient, LLMClient, MockLLMClient
from devai.core.config import DevAIConfig


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


def _mock_embed(text: str) -> list[float]:
    """Deterministic pseudo-embedding for offline use."""
    vec = [0.0] * 16
    for i, char in enumerate(text[:64]):
        vec[i % 16] += ord(char) / 1000.0
    return vec


@dataclass
class Document:
    content: str
    embedding: list[float] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


class VectorStore:
    """In-memory vector store with cosine similarity search."""

    def __init__(self, embedding_client: EmbeddingClient | None = None) -> None:
        self.embedding_client = embedding_client
        self._documents: list[Document] = []

    def add_documents(self, texts: list[str], metadata: list[dict[str, str]] | None = None) -> None:
        meta = metadata or [{} for _ in texts]
        if self.embedding_client:
            embeddings = self.embedding_client.embed(texts)
        else:
            embeddings = [_mock_embed(t) for t in texts]
        for text, emb, md in zip(texts, embeddings, meta):
            self._documents.append(Document(content=text, embedding=emb, metadata=md))

    def search(self, query: str, top_k: int = 3) -> list[Document]:
        if not self._documents:
            return []
        if self.embedding_client:
            query_emb = self.embedding_client.embed([query])[0]
        else:
            query_emb = _mock_embed(query)
        scored = [
            (doc, _cosine_similarity(query_emb, doc.embedding)) for doc in self._documents
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [doc for doc, _ in scored[:top_k]]

    def __len__(self) -> int:
        return len(self._documents)


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        config: DevAIConfig | None = None,
        *,
        store: VectorStore,
        top_k: int = 3,
        system: str | None = None,
    ) -> None:
        self.client = client
        self.config = config or DevAIConfig()
        self.store = store
        self.top_k = top_k
        self.system = system or "Answer based on the provided context. If unsure, say so."

    def query(self, question: str) -> str:
        docs = self.store.search(question, top_k=self.top_k)
        context = "\n\n".join(doc.content for doc in docs)
        prompt = f"Context:\n{context}\n\nQuestion: {question}\n\nAnswer:"
        return self.client.chat(prompt, system=self.system)
