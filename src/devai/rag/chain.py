"""RAG chain for retrieval-augmented generation."""

from __future__ import annotations

from devai.core.client import LLMClient, MockLLMClient
from devai.core.embeddings import EmbeddingClient
from devai.core.models import Message, Role
from devai.rag.store import VectorStore, chunk_text


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        embedding_client: EmbeddingClient | None = None,
        store: VectorStore | None = None,
        top_k: int = 3,
    ) -> None:
        self.client = client
        self.embedding_client = embedding_client
        self.store = store or VectorStore()
        self.top_k = top_k

    def index(self, text: str, chunk_size: int = 500, overlap: int = 50) -> int:
        """Index text into the vector store."""
        if self.embedding_client is None:
            raise ValueError("embedding_client required for indexing")
        chunks = chunk_text(text, chunk_size=chunk_size, overlap=overlap)
        embeddings = self.embedding_client.embed(chunks)
        self.store.add_many(chunks, embeddings)
        return len(chunks)

    def query(self, question: str) -> str:
        """Answer a question using retrieved context."""
        if self.embedding_client is None:
            raise ValueError("embedding_client required for querying")

        query_emb = self.embedding_client.embed_one(question)
        docs = self.store.search(query_emb, top_k=self.top_k)

        if not docs:
            context = "No relevant documents found."
        else:
            context = "\n\n---\n\n".join(doc.content for doc in docs)

        messages = [
            Message(
                role=Role.SYSTEM,
                content=(
                    "Answer the question based on the provided context. "
                    "If the context doesn't contain the answer, say so."
                ),
            ),
            Message(
                role=Role.USER,
                content=f"Context:\n{context}\n\nQuestion: {question}",
            ),
        ]
        response = self.client.chat(messages)
        return response.content
