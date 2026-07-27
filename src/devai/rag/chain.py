"""RAG chain for retrieval-augmented generation."""

from __future__ import annotations

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message
from devai.prompts.dev_prompts import RAG_QUERY
from devai.rag.store import VectorStore


class RAGChain:
    """Retrieve relevant context and generate an answer."""

    def __init__(
        self,
        store: VectorStore,
        config: DevAIConfig | None = None,
        client: LLMClient | None = None,
        top_k: int = 3,
    ) -> None:
        self.store = store
        self.config = config or DevAIConfig.from_env()
        if client:
            self.client = client
        elif self.config.api_key == "mock-key":
            self.client = MockLLMClient(self.config)
        else:
            self.client = LLMClient(self.config)
        self.top_k = top_k

    def query(self, question: str) -> str:
        results = self.store.search(question, top_k=self.top_k)
        context = "\n\n---\n\n".join(doc.content for doc in results) if results else "No context available."
        prompt = RAG_QUERY(context=context, question=question)
        messages = [
            Message.system("Answer based on the provided context."),
            Message.user(prompt),
        ]
        response = self.client.complete(messages)
        return response.content or ""
