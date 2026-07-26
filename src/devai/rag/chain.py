"""RAG (Retrieval-Augmented Generation) components."""

from __future__ import annotations

import math
from typing import Any, Protocol

from devai.core.models import Message, Role


class LLMProtocol(Protocol):
    def complete(self, messages: list[Message], **kwargs: Any) -> Message: ...
    def embed(self, texts: list[str]) -> list[list[float]]: ...


def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
    """Split text into overlapping chunks."""
    if not text:
        return []
    words = text.split()
    if len(words) <= chunk_size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(words):
        end = start + chunk_size
        chunks.append(" ".join(words[start:end]))
        start += chunk_size - overlap
    return chunks


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class VectorStore:
    """Simple in-memory vector store for RAG."""

    def __init__(self) -> None:
        self.documents: list[str] = []
        self.embeddings: list[list[float]] = []
        self.metadata: list[dict[str, Any]] = []

    def add(
        self,
        documents: list[str],
        embeddings: list[list[float]],
        metadata: list[dict[str, Any]] | None = None,
    ) -> None:
        self.documents.extend(documents)
        self.embeddings.extend(embeddings)
        self.metadata.extend(metadata or [{} for _ in documents])

    def search(self, query_embedding: list[float], top_k: int = 5) -> list[dict[str, Any]]:
        scored = [
            (cosine_similarity(query_embedding, emb), i)
            for i, emb in enumerate(self.embeddings)
        ]
        scored.sort(reverse=True)
        results = []
        for score, idx in scored[:top_k]:
            results.append({
                "document": self.documents[idx],
                "score": score,
                "metadata": self.metadata[idx],
            })
        return results

    def __len__(self) -> int:
        return len(self.documents)


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        llm: LLMProtocol,
        store: VectorStore,
        top_k: int = 3,
        system_prompt: str = "Answer based on the provided context. Cite sources when possible.",
    ) -> None:
        self.llm = llm
        self.store = store
        self.top_k = top_k
        self.system_prompt = system_prompt

    def index(self, texts: list[str], chunk_size: int = 500) -> None:
        """Chunk and embed documents into the vector store."""
        all_chunks: list[str] = []
        for text in texts:
            all_chunks.extend(chunk_text(text, chunk_size=chunk_size))
        embeddings = self.llm.embed(all_chunks)
        self.store.add(all_chunks, embeddings)

    def query(self, question: str) -> str:
        query_emb = self.llm.embed([question])[0]
        results = self.store.search(query_emb, top_k=self.top_k)
        context = "\n\n".join(
            f"[Source {i+1}] (score: {r['score']:.3f})\n{r['document']}"
            for i, r in enumerate(results)
        )
        messages = [
            Message(role=Role.SYSTEM, content=self.system_prompt),
            Message(
                role=Role.USER,
                content=f"Context:\n{context}\n\nQuestion: {question}",
            ),
        ]
        return self.llm.complete(messages).content
