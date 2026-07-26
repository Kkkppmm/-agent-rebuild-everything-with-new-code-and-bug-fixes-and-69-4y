"""Tests for RAG components."""

from devai.core.client import MockLLMClient
from devai.rag.chunking import chunk_text
from devai.rag.store import VectorStore
from devai.rag.chain import RAGChain


class MockEmbedder:
    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[float(len(t)), 1.0, 0.0] for t in texts]


class TestChunkText:
    def test_empty(self):
        assert chunk_text("") == []

    def test_small_text(self):
        chunks = chunk_text("Hello world", chunk_size=100)
        assert len(chunks) == 1

    def test_large_text(self):
        text = "word " * 200
        chunks = chunk_text(text, chunk_size=50, overlap=10)
        assert len(chunks) > 1

    def test_separator_splitting(self):
        text = "line1\nline2\nline3\nline4"
        chunks = chunk_text(text, chunk_size=12, separator="\n")
        assert len(chunks) >= 1


class TestVectorStore:
    def test_add_and_search_keyword(self):
        store = VectorStore()
        store.add("Python is a programming language")
        store.add("JavaScript runs in browsers")
        results = store.search("Python programming")
        assert len(results) >= 1
        assert "Python" in results[0].content

    def test_embedder_search(self):
        store = VectorStore(embedder=MockEmbedder())
        store.add("short")
        store.add("a much longer document about testing")
        results = store.search("longer document", top_k=1)
        assert len(results) == 1

    def test_add_many(self):
        store = VectorStore()
        store.add_many(["doc1", "doc2", "doc3"])
        assert len(store) == 3

    def test_clear(self):
        store = VectorStore()
        store.add("test")
        store.clear()
        assert len(store) == 0


class TestRAGChain:
    def test_ingest_and_run(self):
        llm = MockLLMClient(responses=["DevAI is a Python library."])
        store = VectorStore()
        chain = RAGChain(llm, store)
        count = chain.ingest("DevAI helps developers build AI apps. " * 10)
        assert count > 0
        answer = chain.run("What is DevAI?")
        assert "DevAI" in answer
