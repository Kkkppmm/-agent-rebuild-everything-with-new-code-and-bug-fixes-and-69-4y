"""In-memory vector store for RAG."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from devai.core.client import EmbeddingClient
from devai.core.config import DevAIConfig
from devai.rag.chunker import Document


@dataclass
class StoredDocument:
    content: str
    embedding: list[float]
    metadata: dict[str, str] = field(default_factory=dict)


class VectorStore:
    """Simple in-memory vector store with cosine similarity search."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.config = config or DevAIConfig.from_env()
        self.embedder = EmbeddingClient(self.config)
        self._documents: list[StoredDocument] = []

    def add_documents(self, documents: list[Document]) -> None:
        if not documents:
            return
        texts = [d.content for d in documents]
        embeddings = self.embedder.embed(texts)
        for doc, emb in zip(documents, embeddings):
            self._documents.append(
                StoredDocument(content=doc.content, embedding=emb, metadata=doc.metadata)
            )

    def add_text(self, text: str, metadata: dict[str, str] | None = None) -> None:
        from devai.rag.chunker import chunk_text

        self.add_documents(chunk_text(text, metadata=metadata))

    def search(self, query: str, top_k: int = 3) -> list[StoredDocument]:
        if not self._documents:
            return []
        query_emb = self.embedder.embed([query])[0]
        scored = [(cosine_similarity(query_emb, doc.embedding), doc) for doc in self._documents]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored[:top_k]]

    def __len__(self) -> int:
        return len(self._documents)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
