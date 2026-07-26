"""RAG chain for retrieval-augmented generation."""

from __future__ import annotations

from dataclasses import dataclass, field

from devai.core.client import EmbeddingClient, LLMClient
from devai.core.messages import Message
from devai.rag.chunking import chunk_text
from devai.rag.vector_store import VectorStore


@dataclass
class RAGChain:
    """Retrieval-augmented generation chain."""

    client: LLMClient
    embedding_client: EmbeddingClient
    store: VectorStore = field(default_factory=VectorStore)
    chunk_size: int = 500
    top_k: int = 5
    system_prompt: str = (
        "Answer the question based on the provided context. "
        "If the context doesn't contain the answer, say so."
    )

    def ingest(self, text: str, metadata: dict[str, str] | None = None) -> int:
        """Chunk and embed text into the vector store."""
        chunks = chunk_text(text, chunk_size=self.chunk_size)
        if metadata:
            for chunk in chunks:
                chunk.metadata = metadata
        texts = [c.content for c in chunks]
        embeddings = self.embedding_client.embed(texts)
        self.store.add_chunks(chunks, embeddings)
        return len(chunks)

    def query(self, question: str) -> str:
        """Retrieve relevant context and generate an answer."""
        query_embedding = self.embedding_client.embed_one(question)
        results = self.store.search(query_embedding, top_k=self.top_k)
        context = "\n\n".join(r.document.content for r in results)
        messages = [
            Message.system(self.system_prompt),
            Message.user(f"Context:\n{context}\n\nQuestion: {question}"),
        ]
        response = self.client.complete(messages)
        return response.content

    async def aquery(self, question: str) -> str:
        query_embedding = self.embedding_client.embed_one(question)
        results = self.store.search(query_embedding, top_k=self.top_k)
        context = "\n\n".join(r.document.content for r in results)
        messages = [
            Message.system(self.system_prompt),
            Message.user(f"Context:\n{context}\n\nQuestion: {question}"),
        ]
        response = await self.client.acomplete(messages)
        return response.content
