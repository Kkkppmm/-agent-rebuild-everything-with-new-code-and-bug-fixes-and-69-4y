"""Semantic RAG example using DevAI embeddings."""

from devai import MockEmbeddingClient, MockLLMClient
from devai.rag.semantic import SemanticRAGChain, SemanticVectorStore

# Use mock clients — swap for EmbeddingClient + LLMClient with your API key
embedder = MockEmbeddingClient()
client = MockLLMClient(default_response="DevAI is a Python AI library for developers.")

store = SemanticVectorStore(embedder)
store.add_texts(
    [
        "DevAI provides code review, agents, RAG, and a CLI for developers.",
        "Vector stores can use TF-IDF or embedding-based semantic search.",
    ]
)

chain = SemanticRAGChain(client, store, top_k=2)
answer = chain.query("What does DevAI offer?")
print(answer)
