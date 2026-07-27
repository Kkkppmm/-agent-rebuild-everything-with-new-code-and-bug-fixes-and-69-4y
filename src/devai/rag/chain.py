"""RAG chain for retrieval-augmented generation."""

from __future__ import annotations

from devai.core.client import EmbeddingClient, LLMClient, MockLLMClient
from devai.core.models import Message, Role
from devai.rag.vectorstore import VectorStore


class RAGChain:
  """Retrieval-augmented generation chain."""

  def __init__(
    self,
    client: LLMClient | MockLLMClient,
    store: VectorStore,
    embedding_client: EmbeddingClient | None = None,
    top_k: int = 3,
  ) -> None:
    self.client = client
    self.store = store
    self.embedding_client = embedding_client
    self.top_k = top_k

  def query(self, question: str) -> str:
    docs = self._retrieve(question)
    context = "\n\n---\n\n".join(d.content for d in docs)
    prompt = f"""Answer the question based on the following context.
If the context doesn't contain enough information, say so.

Context:
{context}

Question: {question}"""
    messages = [Message(role=Role.USER, content=prompt)]
    return self.client.complete(messages).content

  def _retrieve(self, question: str):
    if self.embedding_client and any(d.embedding for d in self.store.documents):
      query_emb = self.embedding_client.embed_one(question)
      return self.store.search(query_emb, top_k=self.top_k)
    return self.store.search_text(question, top_k=self.top_k)

  def index(self, texts: list[str]) -> None:
    """Add texts and compute embeddings if an embedding client is available."""
    self.store.add_documents(texts)
    if self.embedding_client:
      embeddings = self.embedding_client.embed(texts)
      self.store.add_embeddings(embeddings)
