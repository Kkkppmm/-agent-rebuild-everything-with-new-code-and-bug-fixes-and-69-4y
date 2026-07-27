"""Tests for DevAI RAG."""

from devai.rag import chunk_text, VectorStore, RAGChain
from devai.core.client import MockLLMClient, EmbeddingClient
from devai.core.config import DevAIConfig


class TestChunkText:
    def test_basic(self):
        text = "a" * 1000
        chunks = chunk_text(text, chunk_size=300, overlap=50)
        assert len(chunks) > 1
        assert all(len(c) <= 300 for c in chunks)

    def test_empty(self):
        assert chunk_text("") == []

    def test_short_text(self):
        chunks = chunk_text("short", chunk_size=100)
        assert len(chunks) == 1


class TestVectorStore:
    def test_add_and_search(self):
        store = VectorStore(EmbeddingClient(DevAIConfig(provider="mock")))
        store.add("Python is a programming language")
        store.add("JavaScript runs in browsers")
        results = store.search("programming language")
        assert len(results) > 0

    def test_add_text(self):
        store = VectorStore(EmbeddingClient(DevAIConfig(provider="mock")))
        docs = store.add_text("word " * 200, chunk_size=100)
        assert len(docs) > 1

    def test_clear(self):
        store = VectorStore(EmbeddingClient(DevAIConfig(provider="mock")))
        store.add("test")
        store.clear()
        assert len(store) == 0


class TestRAGChain:
    def test_run(self):
        store = VectorStore(EmbeddingClient(DevAIConfig(provider="mock")))
        store.add("DevAI is a Python AI library for developers")
        client = MockLLMClient(responses=["DevAI helps developers with AI tasks."])
        chain = RAGChain(client=client, vector_store=store)
        result = chain.run("What is DevAI?")
        assert "DevAI" in result

    def test_index(self):
        store = VectorStore(EmbeddingClient(DevAIConfig(provider="mock")))
        client = MockLLMClient()
        chain = RAGChain(client=client, vector_store=store)
        count = chain.index("Some long text " * 50, chunk_size=100)
        assert count > 0
