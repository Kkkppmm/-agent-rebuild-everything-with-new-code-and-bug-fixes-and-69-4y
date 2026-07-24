"""RAG (retrieval-augmented generation) example."""

from devai.core.client import MockLLMClient, EmbeddingClient
from devai.core.config import DevAIConfig
from devai.rag import RAGChain, VectorStore, chunk_text

DOCS = """
DevAI is a Python AI library for developers.
It provides LLM clients, prompts, agents, chains, and RAG utilities.
Use MockLLMClient for testing without API keys.
"""


def main() -> None:
    config = DevAIConfig(provider="mock")
    embedder = EmbeddingClient(config=config)
    store = VectorStore(embedding_client=embedder)

    for i, chunk in enumerate(chunk_text(DOCS, chunk_size=100)):
        store.add(chunk, metadata={"id": f"chunk-{i}"})

    client = MockLLMClient(responses=["DevAI helps developers build AI-powered tools."])
    rag = RAGChain(client=client, vector_store=store)

    answer = rag.run("What is DevAI?")
    print("Answer:", answer)


if __name__ == "__main__":
    main()
