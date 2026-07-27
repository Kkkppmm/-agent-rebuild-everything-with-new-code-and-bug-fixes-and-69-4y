"""Tests for RAG."""

from devai import MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text


def test_chunk_text():
    text = "a" * 1000
    chunks = chunk_text(text, chunk_size=200, overlap=20)
    assert len(chunks) > 1
    assert all(len(c) <= 200 for c in chunks)


def test_chunk_empty():
    assert chunk_text("") == []


def test_vector_store():
    store = VectorStore()
    store.add_documents(["Python is great", "JavaScript is popular", "Rust is fast"])
    assert store.size == 3
    results = store.search("Python programming", top_k=1)
    assert len(results) == 1


def test_rag_chain():
    store = VectorStore()
    store.add_documents(["DevAI is a Python library for developers."])
    chain = RAGChain(client=MockLLMClient(), store=store)
    answer = chain.query("What is DevAI?")
    assert isinstance(answer, str)
    assert len(answer) > 0
