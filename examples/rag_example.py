"""RAG example with mock embeddings."""

from devai.core.client import MockLLMClient
from devai.core.config import DevAIConfig
from devai.rag import VectorStore, chunk_text


class MockEmbeddingClient:
  """Simple mock that returns deterministic embeddings."""

  def embed(self, texts: list[str]) -> list[list[float]]:
      return [[hash(t) % 100 / 100.0, len(t) / 1000.0] for t in texts]

  def embed_one(self, text: str) -> list[float]:
      return self.embed([text])[0]


def main() -> None:
    docs = """
    DevAI is a Python AI library for developers.
    It provides LLM clients, agents, chains, RAG, and developer tools.
    Use MockLLMClient for testing without API keys.
  """

    chunks = chunk_text(docs.strip(), chunk_size=100)
    embedder = MockEmbeddingClient()
    store = VectorStore()

    embeddings = embedder.embed([c.content for c in chunks])
    store.add_chunks(chunks, embeddings)

    query_emb = embedder.embed_one("What is DevAI?")
    results = store.search(query_emb, top_k=2)

    print(f"Found {len(results)} relevant chunks:")
    for r in results:
        print(f"  [{r.score:.3f}] {r.document.content[:80]}...")


if __name__ == "__main__":
    main()
