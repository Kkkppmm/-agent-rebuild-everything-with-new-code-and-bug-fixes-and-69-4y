"""Tests for RAG components."""

from devai.rag.chunking import chunk_text
from devai.rag.vector_store import VectorStore
from devai.rag.rag_chain import RAGChain
from devai.core.client import MockLLMClient


def test_chunk_text_short():
    assert chunk_text("short") == ["short"]


def test_chunk_text_long():
    text = "word " * 200
    chunks = chunk_text(text, chunk_size=50, overlap=10)
    assert len(chunks) > 1


def test_chunk_text_with_separator():
    text = "line1\nline2\nline3\nline4"
    chunks = chunk_text(text, chunk_size=10, separator="\n")
    assert len(chunks) >= 1


def test_vector_store_add_and_search():
    store = VectorStore()
    store.add("Python is a programming language")
    store.add("JavaScript runs in browsers")
    results = store.search("Python programming")
    assert len(results) > 0
    assert results[0]["score"] > 0


def test_vector_store_delete():
    store = VectorStore()
    doc_id = store.add("temporary doc")
    assert store.delete(doc_id)
    assert len(store) == 0


def test_vector_store_batch():
    store = VectorStore()
    ids = store.add_batch(["doc1", "doc2", "doc3"])
    assert len(ids) == 3


def test_rag_chain():
    client = MockLLMClient(responses=["Python uses asyncio for concurrency"])
    rag = RAGChain(client, top_k=2)
    rag.index([
        "Python asyncio provides async/await syntax",
        "Threading uses OS threads for parallelism",
    ])
    result = rag.query("How does Python handle async?")
    assert "asyncio" in result.lower() or len(result) > 0
