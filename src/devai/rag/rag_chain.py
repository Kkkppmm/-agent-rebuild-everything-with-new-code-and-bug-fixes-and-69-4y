"""RAG chain combining retrieval with generation."""

from typing import Any, Protocol

from devai.core.models import Message, Role
from devai.rag.chunking import chunk_text
from devai.rag.vector_store import VectorStore


class LLMProtocol(Protocol):
    def complete(self, messages: list[Message], **kwargs: Any) -> Message: ...


class RAGChain:
    """Retrieval-augmented generation chain."""

    def __init__(
        self,
        client: LLMProtocol,
        store: VectorStore | None = None,
        chunk_size: int = 500,
        top_k: int = 3,
        system_prompt: str = "Answer based on the provided context. Cite sources when possible.",
    ) -> None:
        self.client = client
        self.store = store or VectorStore()
        self.chunk_size = chunk_size
        self.top_k = top_k
        self.system_prompt = system_prompt

    def index(self, documents: list[str], metadatas: list[dict] | None = None) -> list[str]:
        ids = []
        for i, doc in enumerate(documents):
            chunks = chunk_text(doc, chunk_size=self.chunk_size)
            meta = metadatas[i] if metadatas else {}
            for chunk in chunks:
                ids.append(self.store.add(chunk, metadata=meta))
        return ids

    def query(self, question: str, **kwargs: Any) -> str:
        results = self.store.search(question, top_k=self.top_k)
        context = "\n\n".join(
            f"[Source {i+1}] (score: {r['score']:.3f})\n{r['text']}"
            for i, r in enumerate(results)
        )
        messages = [
            Message(role=Role.SYSTEM, content=self.system_prompt),
            Message(
                role=Role.USER,
                content=f"Context:\n{context}\n\nQuestion: {question}",
            ),
        ]
        response = self.client.complete(messages, **kwargs)
        return response.content
