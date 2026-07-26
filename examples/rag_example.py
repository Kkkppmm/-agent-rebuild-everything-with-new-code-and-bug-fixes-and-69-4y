"""RAG pipeline for codebase Q&A (mock embeddings)."""

from devai.core.client import MockLLMClient, EmbeddingClient
from devai.core.config import DevAIConfig
from devai.rag import RAGChain, VectorStore

DOCS = """
DevAI is a Python AI library for developers.
It provides LLM clients, agents, chains, and RAG utilities.
Use MockLLMClient for testing without API keys.
The CLI supports review, explain, debug, and commit commands.
"""

def main() -> None:
    config = DevAIConfig(provider="mock")
    store = VectorStore(embedding_client=EmbeddingClient(config))
    store.add_text(DOCS, chunk_size=100)

    client = MockLLMClient(responses=[
        "DevAI is a Python AI library with LLM clients, agents, and RAG."
    ])
    rag = RAGChain(client=client, vector_store=store)
    answer = rag.run("What is DevAI?")
    print(answer)

if __name__ == "__main__":
    main()
