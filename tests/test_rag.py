"""Tests for RAG components."""

from devai import DevAIConfig, MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text


def test_chunk_text():
    text = "a" * 1000
    chunks = chunk_text(text, chunk_size=300, overlap=50)
    assert len(chunks) >= 3
    assert all(len(c) <= 300 for c in chunks)


def test_chunk_text_empty():
    assert chunk_text("") == []


def test_vector_store_add_and_search():
    store = VectorStore()
    store.add_documents(
        [
            "Python uses indentation for blocks.",
            "JavaScript uses curly braces.",
            "Rust has ownership semantics.",
        ]
    )
    assert len(store) == 3
    results = store.search("Python indentation")
    assert len(results) > 0
    assert "Python" in results[0].content


def test_rag_chain():
    store = VectorStore()
    store.add_documents(["DevAI is a Python AI library for developers."])
    client = MockLLMClient(responses=["DevAI helps developers build AI apps."])
    rag = RAGChain(client, DevAIConfig(), store=store)
    answer = rag.query("What is DevAI?")
    assert "DevAI" in answer
