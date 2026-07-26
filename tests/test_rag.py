"""Tests for RAG components."""

from devai.core.client import MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text, cosine_similarity


class TestChunkText:
    def test_short_text(self):
        assert chunk_text("hello") == ["hello"]

    def test_long_text(self):
        text = "word " * 200
        chunks = chunk_text(text, chunk_size=100, overlap=10)
        assert len(chunks) > 1
        assert all(len(c) <= 200 for c in chunks)


class TestCosineSimilarity:
    def test_identical(self):
        assert cosine_similarity([1, 0, 0], [1, 0, 0]) == 1.0

    def test_orthogonal(self):
        assert cosine_similarity([1, 0], [0, 1]) == 0.0


class TestVectorStore:
    def test_add_and_search(self):
        store = VectorStore()
        store.add_documents([
            "Python is a programming language",
            "JavaScript runs in browsers",
            "Rust is systems programming",
        ])
        results = store.search("Python programming", top_k=2)
        assert len(results) == 2
        assert results[0]["score"] > 0

    def test_empty_store(self):
        store = VectorStore()
        assert store.search("test") == []


class TestRAGChain:
    def test_query(self):
        store = VectorStore()
        store.add_documents([
            "DevAI is a Python AI library for developers.",
            "It supports agents, RAG, and tool calling.",
        ])
        client = MockLLMClient(responses=["DevAI is a Python AI library."])
        rag = RAGChain(client=client, vector_store=store)
        answer = rag.query("What is DevAI?")
        assert "DevAI" in answer
