"""Tests for DevAI RAG."""

from devai.core.client import MockLLMClient
from devai.core.embedding import MockEmbeddingClient
from devai.rag import RAGChain, VectorStore, chunk_text, cosine_similarity


def test_chunk_text():
    text = " ".join(f"word{i}" for i in range(100))
    chunks = chunk_text(text, chunk_size=20, overlap=5)
    assert len(chunks) > 1
    assert all(len(c.split()) <= 20 for c in chunks)


def test_cosine_similarity():
    a = [1.0, 0.0, 0.0]
    b = [1.0, 0.0, 0.0]
    assert cosine_similarity(a, b) == 1.0


def test_vector_store():
    store = VectorStore()
    store.add("hello world", [1.0, 0.0, 0.0])
    store.add("goodbye", [0.0, 1.0, 0.0])
    results = store.search([1.0, 0.0, 0.0], top_k=1)
    assert len(results) == 1
    assert "hello" in results[0][0].content


def test_rag_chain():
    llm = MockLLMClient(responses=["DevAI is a Python library."])
    embedder = MockEmbeddingClient()
    rag = RAGChain(llm, embedder)
    rag.add_text("DevAI helps developers build AI applications.")
    answer = rag.query("What is DevAI?")
    assert answer
