"""RAG chain combining retrieval with generation."""

from __future__ import annotations

from typing import Any, Protocol

from devai.core.models import Message, Role
from devai.rag.store import VectorStore


class LLMProtocol(Protocol):
    def complete(self, prompt: str, **kwargs: Any) -> str: ...


RAG_PROMPT = """Answer the question based on the provided context.
If the context doesn't contain enough information, say so.

Context:
{context}

Question: {question}

Answer:"""


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        llm: LLMProtocol,
        store: VectorStore,
        *,
        top_k: int = 3,
        system: str | None = None,
    ) -> None:
        self.llm = llm
        self.store = store
        self.top_k = top_k
        self.system = system

    def run(self, question: str) -> str:
        docs = self.store.search(question, top_k=self.top_k)
        context = "\n\n---\n\n".join(doc.content for doc in docs)
        prompt = RAG_PROMPT.format(context=context or "No relevant context found.", question=question)
        return self.llm.complete(prompt, system=self.system)

    def ingest(self, text: str, *, chunk_size: int = 500) -> int:
        from devai.rag.chunking import chunk_text

        chunks = chunk_text(text, chunk_size=chunk_size)
        self.store.add_many(chunks)
        return len(chunks)
