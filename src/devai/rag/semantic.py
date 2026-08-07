"""Semantic vector store using embedding-based retrieval."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from devai.core.client import LLMClientProtocol
from devai.core.models import Message
from devai.rag.store import Document, chunk_text


class EmbeddingProtocol(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...
    def embed_one(self, text: str) -> list[float]: ...


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = sum(x * x for x in a) ** 0.5
    mag_b = sum(x * x for x in b) ** 0.5
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


@dataclass
class SemanticVectorStore:
    """In-memory vector store using embedding similarity."""

    embedder: EmbeddingProtocol
    documents: list[Document] = field(default_factory=list)
    _vectors: list[list[float]] = field(default_factory=list, repr=False)

    def add_texts(
        self,
        texts: list[str],
        metadata: list[dict] | None = None,
        *,
        chunk: bool = False,
        chunk_size: int = 500,
        overlap: int = 50,
    ) -> None:
        """Add texts (optionally chunked) to the store."""
        meta = metadata or [{}] * len(texts)
        for text, m in zip(texts, meta):
            chunks = chunk_text(text, chunk_size, overlap) if chunk else [text]
            for chunk_content in chunks:
                self.documents.append(Document(content=chunk_content, metadata=m))
        self._rebuild_index()

    def add_documents(self, texts: list[str], metadata: list[dict] | None = None) -> None:
        """Add document texts without chunking."""
        self.add_texts(texts, metadata, chunk=False)

    def _rebuild_index(self) -> None:
        if not self.documents:
            self._vectors = []
            return
        self._vectors = self.embedder.embed([doc.content for doc in self.documents])

    def search(self, query: str, top_k: int = 3) -> list[Document]:
        """Return the most similar documents to the query."""
        if not self.documents:
            return []

        query_vec = self.embedder.embed_one(query)
        scores = [
            (i, _cosine_similarity(query_vec, vec))
            for i, vec in enumerate(self._vectors)
        ]
        scores.sort(key=lambda item: item[1], reverse=True)
        return [self.documents[i] for i, score in scores[:top_k] if score > 0]

    def __len__(self) -> int:
        return len(self.documents)


class SemanticRAGChain:
    """RAG chain backed by semantic vector search."""

    def __init__(
        self,
        client: LLMClientProtocol,
        store: SemanticVectorStore,
        top_k: int = 3,
    ) -> None:
        self.client = client
        self.store = store
        self.top_k = top_k

    def query(self, question: str) -> str:
        docs = self.store.search(question, top_k=self.top_k)
        context = (
            "\n\n---\n\n".join(d.content for d in docs)
            if docs
            else "No relevant documents found."
        )
        messages = [
            Message.system(
                "Answer the question based on the provided context. "
                "If the context doesn't contain the answer, say so."
            ),
            Message.user(f"Context:\n{context}\n\nQuestion: {question}"),
        ]
        return self.client.complete(messages)

    async def aquery(self, question: str) -> str:
        docs = self.store.search(question, top_k=self.top_k)
        context = (
            "\n\n---\n\n".join(d.content for d in docs)
            if docs
            else "No relevant documents found."
        )
        messages = [
            Message.system(
                "Answer the question based on the provided context. "
                "If the context doesn't contain the answer, say so."
            ),
            Message.user(f"Context:\n{context}\n\nQuestion: {question}"),
        ]
        return await self.client.acomplete(messages)
