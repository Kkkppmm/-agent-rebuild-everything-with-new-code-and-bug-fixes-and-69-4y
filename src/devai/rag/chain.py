"""RAG components for DevAI."""

from __future__ import annotations

import math
from dataclasses import dataclass, field


def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
    """Split text into overlapping chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap >= chunk_size:
        raise ValueError("overlap must be less than chunk_size")

    words = text.split()
    if not words:
        return []

    chunks: list[str] = []
    start = 0
    while start < len(words):
        end = start + chunk_size
        chunks.append(" ".join(words[start:end]))
        start += chunk_size - overlap

    return chunks


@dataclass
class Document:
    content: str
    metadata: dict = field(default_factory=dict)
    embedding: list[float] | None = None


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class VectorStore:
    """Simple in-memory vector store."""

    def __init__(self) -> None:
        self.documents: list[Document] = []

    def add(self, content: str, embedding: list[float], metadata: dict | None = None) -> None:
        self.documents.append(Document(content=content, embedding=embedding, metadata=metadata or {}))

    def add_documents(self, docs: list[Document]) -> None:
        self.documents.extend(docs)

    def search(self, query_embedding: list[float], top_k: int = 5) -> list[tuple[Document, float]]:
        scored = []
        for doc in self.documents:
            if doc.embedding is None:
                continue
            score = cosine_similarity(query_embedding, doc.embedding)
            scored.append((doc, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def __len__(self) -> int:
        return len(self.documents)


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(self, llm, embedder, store: VectorStore | None = None, top_k: int = 3):
        self.llm = llm
        self.embedder = embedder
        self.store = store or VectorStore()
        self.top_k = top_k

    def add_text(self, text: str, metadata: dict | None = None) -> None:
        for chunk in chunk_text(text):
            embedding = self.embedder.embed_one(chunk)
            self.store.add(chunk, embedding, metadata)

    def query(self, question: str) -> str:
        from devai.core.models import Message
        from devai.chains.chain import Chain

        query_emb = self.embedder.embed_one(question)
        results = self.store.search(query_emb, top_k=self.top_k)
        context = "\n\n".join(doc.content for doc, _ in results)

        prompt = (
            f"Use the following context to answer the question. "
            f"If the context doesn't contain the answer, say so.\n\n"
            f"Context:\n{context}\n\nQuestion: {question}"
        )
        chain = Chain(self.llm)
        return chain.run(prompt)
