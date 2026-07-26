"""RAG chain combining retrieval and generation."""

from __future__ import annotations

from devai.core.client import EmbeddingClient, LLMClient, MockLLMClient
from devai.core.models import Message, Role
from devai.rag.chunking import chunk_text
from devai.rag.vectorstore import VectorStore


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        embedding_client: EmbeddingClient | None = None,
        *,
        chunk_size: int = 500,
        top_k: int = 3,
    ) -> None:
        self.client = client
        self.embedding_client = embedding_client
        self.chunk_size = chunk_size
        self.top_k = top_k
        self.store = VectorStore()

    def add_documents(self, texts: list[str]) -> None:
        chunks = []
        for text in texts:
            chunks.extend(chunk_text(text, chunk_size=self.chunk_size))

        if self.embedding_client:
            embeddings = self.embedding_client.embed(chunks)
            self.store.add_with_embeddings(chunks, embeddings)
        else:
            for chunk in chunks:
                self.store.add(chunk)

    def _retrieve(self, query: str) -> list[str]:
        if self.embedding_client and len(self.store) > 0:
            query_emb = self.embedding_client.embed([query])[0]
            docs = self.store.search(query_emb, top_k=self.top_k)
            return [d.content for d in docs]
        all_docs = [d.content for d in self.store.documents]
        query_lower = query.lower()
        scored = [
            (sum(1 for word in query_lower.split() if word in doc.lower()), doc)
            for doc in all_docs
        ]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in scored[: self.top_k] if score > 0]

    def run(self, query: str) -> str:
        context_docs = self._retrieve(query)
        context = "\n\n---\n\n".join(context_docs) if context_docs else "No relevant context found."

        messages = [
            Message(
                role=Role.SYSTEM,
                content="Answer questions based on the provided context. "
                "If the context doesn't contain the answer, say so.",
            ),
            Message(
                role=Role.USER,
                content=f"Context:\n{context}\n\nQuestion: {query}",
            ),
        ]
        return self.client.complete(messages).content
