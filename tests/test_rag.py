"""Tests for RAG components."""

from devai import MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text


def test_chunk_text_short():
    assert chunk_text("hello") == ["hello"]


def test_chunk_text_long():
    text = "word " * 200
    chunks = chunk_text(text, chunk_size=100, overlap=10)
    assert len(chunks) > 1
    assert all(len(c) <= 150 for c in chunks)


def test_chunk_text_empty():
    assert chunk_text("") == []
    assert chunk_text("   ") == []


def test_vector_store_add():
    store = VectorStore()
    store.add("hello world")
    assert len(store) == 1


def test_vector_store_search():
    store = VectorStore()
    store.add_with_embeddings(
        ["python is great", "javascript is fine"],
        [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]],
    )
    results = store.search([0.9, 0.1, 0.0], top_k=1)
    assert len(results) == 1
    assert "python" in results[0].content


def test_rag_chain_keyword():
    client = MockLLMClient(responses=["Use pip install devai."])
    rag = RAGChain(client)
    rag.add_documents(["DevAI is installed via pip install devai."])
    result = rag.run("How to install DevAI?")
    assert len(result) > 0


def test_vector_store_clear():
    store = VectorStore()
    store.add("test")
    store.clear()
    assert len(store) == 0
