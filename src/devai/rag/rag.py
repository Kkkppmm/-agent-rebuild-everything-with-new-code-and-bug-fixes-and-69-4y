"""RAG (Retrieval-Augmented Generation) for DevAI."""

import math
from dataclasses import dataclass, field
from typing import Any

from devai.core.client import EmbeddingClient, LLMClient, MockLLMClient


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


@dataclass
class Document:
    """A document with optional metadata."""

    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    embedding: list[float] | None = None


class VectorStore:
    """Simple in-memory vector store."""

    def __init__(self, embedding_client: EmbeddingClient | None = None) -> None:
        self.embedding_client = embedding_client or EmbeddingClient()
        self.documents: list[Document] = []

    def add(self, content: str, metadata: dict[str, Any] | None = None) -> Document:
        embedding = self.embedding_client.embed_one(content)
        doc = Document(content=content, metadata=metadata or {}, embedding=embedding)
        self.documents.append(doc)
        return doc

    def add_text(self, text: str, chunk_size: int = 500, metadata: dict[str, Any] | None = None) -> list[Document]:
        chunks = chunk_text(text, chunk_size=chunk_size)
        return [self.add(chunk, metadata) for chunk in chunks]

    def search(self, query: str, top_k: int = 3) -> list[Document]:
        if not self.documents:
            return []
        query_embedding = self.embedding_client.embed_one(query)
        scored = []
        for doc in self.documents:
            if doc.embedding:
                score = _cosine_similarity(query_embedding, doc.embedding)
                scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored[:top_k]]

    def clear(self) -> None:
        self.documents.clear()

    def __len__(self) -> int:
        return len(self.documents)


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        vector_store: VectorStore,
        top_k: int = 3,
    ) -> None:
        self.client = client
        self.vector_store = vector_store
        self.top_k = top_k

    def run(self, query: str) -> str:
        docs = self.vector_store.search(query, top_k=self.top_k)
        context = "\n\n".join(doc.content for doc in docs)
        prompt = (
            f"Use the following context to answer the question.\n\n"
            f"Context:\n{context}\n\n"
            f"Question: {query}"
        )
        response = self.client.complete(prompt)
        return response.content

    def index(self, text: str, chunk_size: int = 500) -> int:
        docs = self.vector_store.add_text(text, chunk_size=chunk_size)
        return len(docs)
