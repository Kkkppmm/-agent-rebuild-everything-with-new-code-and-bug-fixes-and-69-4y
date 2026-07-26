"""Tests for RAG components."""

from devai.core.client import MockLLMClient
from devai.rag.chain import RAGChain, VectorStore, chunk_text, cosine_similarity


def test_chunk_text_short():
    assert chunk_text("hello world") == ["hello world"]


def test_chunk_text_long():
    words = " ".join(f"w{i}" for i in range(100))
    chunks = chunk_text(words, chunk_size=20, overlap=5)
    assert len(chunks) > 1


def test_chunk_text_empty():
    assert chunk_text("") == []


def test_cosine_similarity():
    assert cosine_similarity([1, 0], [1, 0]) == 1.0
    assert cosine_similarity([1, 0], [0, 1]) == 0.0


def test_vector_store():
    store = VectorStore()
    store.add(["doc1", "doc2"], [[1, 0], [0, 1]])
    results = store.search([1, 0], top_k=1)
    assert results[0]["document"] == "doc1"
    assert results[0]["score"] > 0.9


def test_rag_chain():
    client = MockLLMClient(responses=["The answer is 42"])
    store = VectorStore()
    store.add(
        ["The meaning of life is 42"],
        client.embed(["The meaning of life is 42"]),
    )
    rag = RAGChain(client, store)
    result = rag.query("What is the meaning of life?")
    assert "42" in result


def test_rag_index():
    client = MockLLMClient(responses=["answer"])
    rag = RAGChain(client, VectorStore())
    rag.index(["Short doc", "Another document here"])
    assert len(rag.store) > 0
