"""Retrieval-augmented generation chain."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devai.chains.chain import Chain
from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.mock import MockLLMClient
from devai.prompts.template import PromptTemplate
from devai.rag.chunker import chunk_text
from devai.rag.store import Document, VectorStore

RAG_PROMPT = PromptTemplate(
    """Answer the question using only the provided context. If the context is insufficient, say so.

**Context:**
{context}

**Question:** {question}

Provide a clear, concise answer for a developer audience."""
)


class RAGChain:
    """Retrieve relevant documents, then generate an answer with an LLM."""

    def __init__(
        self,
        store: VectorStore | None = None,
        prompt: PromptTemplate | str = RAG_PROMPT,
        client: LLMClient | MockLLMClient | None = None,
        config: DevAIConfig | None = None,
        top_k: int = 4,
    ):
        self.store = store or VectorStore()
        self.top_k = top_k
        self.config = config or DevAIConfig()
        self.chain = Chain(prompt, client=client, config=self.config)

    async def ingest(self, texts: list[str], metadata: list[dict[str, Any]] | None = None) -> int:
        return await self.store.add(texts, metadata=metadata)

    def ingest_sync(self, texts: list[str], metadata: list[dict[str, Any]] | None = None) -> int:
        return self.store.add_sync(texts, metadata=metadata)

    async def ingest_file(
        self,
        path: str | Path,
        *,
        chunk_size: int = 800,
        overlap: int = 100,
    ) -> int:
        file_path = Path(path)
        text = file_path.read_text(encoding="utf-8", errors="replace")
        chunks = chunk_text(text, chunk_size=chunk_size, overlap=overlap)
        metadata = [{"source": str(file_path), "chunk": i} for i in range(len(chunks))]
        return await self.ingest(chunks, metadata=metadata)

    def ingest_file_sync(self, path: str | Path, **kwargs: Any) -> int:
        import asyncio

        return asyncio.run(self.ingest_file(path, **kwargs))

    async def retrieve(self, question: str) -> list[Document]:
        return await self.store.search(question, top_k=self.top_k)

    def _format_context(self, documents: list[Document]) -> str:
        if not documents:
            return "No relevant context found."
        parts: list[str] = []
        for index, doc in enumerate(documents, start=1):
            source = doc.metadata.get("source", "unknown")
            parts.append(f"[{index}] ({source})\n{doc.content}")
        return "\n\n".join(parts)

    async def run(self, question: str) -> str:
        documents = await self.retrieve(question)
        context = self._format_context(documents)
        return await self.chain.run(question=question, context=context)

    def run_sync(self, question: str) -> str:
        import asyncio

        return asyncio.run(self.run(question))

    async def close(self) -> None:
        await self.chain.close()
