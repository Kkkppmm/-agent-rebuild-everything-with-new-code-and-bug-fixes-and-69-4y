"""Tests for RAG."""

from devai.core.client import MockLLMClient
from devai.rag.rag import RAGChain, VectorStore, chunk_text, _cosine_similarity


def test_chunk_text_short():
    assert chunk_text("hello") == ["hello"]


def test_chunk_text_long():
    text = "paragraph one\n\nparagraph two\n\nparagraph three"
    chunks = chunk_text(text, chunk_size=20, overlap=5)
    assert len(chunks) >= 2


def test_chunk_text_empty():
    assert chunk_text("") == []


def test_cosine_similarity():
    assert _cosine_similarity([1, 0], [1, 0]) == 1.0
    assert _cosine_similarity([1, 0], [0, 1]) == 0.0


def test_vector_store_keyword_search():
    store = VectorStore()
    store.add(["Python is a programming language", "JavaScript runs in browsers"])
    results = store.search("Python programming", top_k=1)
    assert len(results) == 1
    assert "Python" in results[0]["document"]


def test_vector_store_with_embeddings():
    store = VectorStore()
    store.add_with_embeddings(
        ["hello world", "goodbye world"],
        [[1.0, 0.0], [0.0, 1.0]],
    )
    results = store.search("hello", top_k=1)
    assert len(results) == 1


def test_vector_store_clear():
    store = VectorStore()
    store.add(["doc1"])
    store.clear()
    assert len(store) == 0


def test_rag_chain():
    client = MockLLMClient(responses=["Python is a programming language."])
    store = VectorStore()
    store.add(["Python is great for AI and web development."])
    rag = RAGChain(client, store)
    result = rag.run("What is Python?")
    assert "Python" in result


def test_rag_add_documents():
    client = MockLLMClient(responses=["answer"])
    store = VectorStore()
    rag = RAGChain(client, store)
    count = rag.add_documents("word " * 200, chunk_size=100)
    assert count >= 1
